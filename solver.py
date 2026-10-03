"""2captcha solving for your own scripts, routed through the residential proxy.

Use from any script:

    import sys; sys.path.insert(0, "/path/to/resproxy")
    import solver

    token = solver.recaptcha_v2(site_key, page_url)   # put into g-recaptcha-response
    token = solver.turnstile(site_key, page_url)      # put into cf-turnstile-response
    text  = solver.image(open("captcha.png", "rb").read())
    proxies = solver.proxies()                        # for requests.get(..., proxies=proxies)

Solving only happens while the captcha switch is ON (dashboard key 5).
When it is off, every solve raises CaptchaOff so your script can fall back.
"""

import base64
import http.client
import json
import time
import urllib.parse
import urllib.request

import resproxy

API = "https://api.2captcha.com"
FLAG_FILE = resproxy.STATE_DIR / "captcha-enabled"


class CaptchaOff(Exception):
    pass


class CaptchaError(Exception):
    pass


class CaptchaNetworkError(CaptchaError):
    """Could not reach 2captcha or got a garbled reply. Usually temporary."""


# ------------------------------------------------------------------ switch

def is_enabled():
    try:
        return FLAG_FILE.is_file()
    except OSError:
        # Older Pythons raise here when the state folder can't be searched.
        return False


def set_enabled(on):
    try:
        resproxy.make_dir(resproxy.STATE_DIR)
        if FLAG_FILE.exists() and not FLAG_FILE.is_file():
            raise CaptchaError(f"{FLAG_FILE} is not a file; remove it and try again")
        if on:
            FLAG_FILE.touch()
        else:
            FLAG_FILE.unlink(missing_ok=True)
    except OSError as e:
        raise CaptchaError(f"Could not write {FLAG_FILE}: {e.strerror or e}") from None


# ------------------------------------------------------------------ helpers

def _config():
    try:
        return resproxy.load_config()
    except resproxy.ConfigError as e:
        raise CaptchaError(str(e)) from None


def proxies():
    """requests-style proxies dict that goes straight to the residential proxy."""
    cfg = _config()
    login = f"{urllib.parse.quote(cfg['username'], safe='')}:{urllib.parse.quote(cfg['password'], safe='')}"
    url = f"http://{login}@{cfg['upstream_host']}:{cfg['upstream_port']}"
    return {"http": url, "https": url}


def _call(method, payload, timeout=30):
    req = urllib.request.Request(
        f"{API}/{method}", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except (OSError, ValueError, http.client.HTTPException) as e:
        raise CaptchaNetworkError(f"{method}: {e}") from e
    if not isinstance(data, dict):
        raise CaptchaNetworkError(f"{method}: unexpected reply {str(data)[:80]}")
    if str(data.get("errorId") or 0) != "0":
        raise CaptchaError(f"{data.get('errorCode')}: {data.get('errorDescription')}")
    return data


def api_key():
    key = _config().get("captcha_api_key") or ""
    key = str(key) if isinstance(key, (str, int)) and not isinstance(key, bool) else ""
    if not key or key.startswith("YOUR_"):
        raise CaptchaError("Add your 2captcha API key as captcha_api_key in config.json")
    return key


def balance():
    key = api_key()
    res = _call("getBalance", {"clientKey": key})
    b = res.get("balance")
    if not isinstance(b, (int, float)) or isinstance(b, bool):
        raise CaptchaError(f"getBalance: no balance in reply {str(res)[:80]}")
    return b


def _proxy_fields():
    cfg = _config()
    return {"proxyType": "http", "proxyAddress": cfg["upstream_host"],
            "proxyPort": cfg["upstream_port"], "proxyLogin": cfg["username"],
            "proxyPassword": cfg["password"]}


def solve(task, timeout=180):
    """Send a raw 2captcha task and wait for the solution dict."""
    if not is_enabled():
        raise CaptchaOff("Captcha solving is switched off. Turn it on in the dashboard (key 5).")
    key = api_key()
    # createTask is not retried: a lost reply may still have created (and
    # charged for) a task.
    res = _call("createTask", {"clientKey": key, "task": task})
    task_id = res.get("taskId")
    if not task_id:
        raise CaptchaError(f"createTask: no taskId in reply {str(res)[:80]}")
    deadline = time.time() + timeout
    time.sleep(max(0, min(5, timeout)))
    last_error = None
    while True:
        # Poll at least once, and never wait past the deadline for a reply.
        left = deadline - time.time()
        try:
            res = _call("getTaskResult", {"clientKey": key, "taskId": task_id},
                        timeout=max(1, min(30, left)))
        except CaptchaNetworkError as e:
            # The task is already paid for, so ride out a network blip.
            last_error = e
            res = {}
        if res.get("status") == "ready":
            if not isinstance(res.get("solution"), dict):
                raise CaptchaError(f"Task {task_id} is ready but the reply has no solution")
            return res["solution"]
        left = deadline - time.time()
        if left <= 0:
            break
        time.sleep(min(5, left))
    raise CaptchaError(f"Timed out after {timeout}s (task {task_id})"
                       + (f", last error: {last_error}" if last_error else ""))


# --------------------------------------------------------------- task types
# use_proxy=True makes 2captcha solve from the residential proxy, so the
# token matches the IP your script uses. Slower and costs a bit more;
# turn it off if the site doesn't care.

def _field(solution, key):
    if not isinstance(solution.get(key), str):
        raise CaptchaError(f"The solution has no {key}: {str(solution)[:80]}")
    return solution[key]


def recaptcha_v2(site_key, page_url, use_proxy=True, invisible=False):
    task = {"websiteURL": page_url, "websiteKey": site_key, "isInvisible": invisible}
    if use_proxy:
        task.update(type="RecaptchaV2Task", **_proxy_fields())
    else:
        task["type"] = "RecaptchaV2TaskProxyless"
    return _field(solve(task), "gRecaptchaResponse")


def recaptcha_v3(site_key, page_url, action="verify", min_score=0.7):
    task = {"type": "RecaptchaV3TaskProxyless", "websiteURL": page_url,
            "websiteKey": site_key, "pageAction": action, "minScore": min_score}
    return _field(solve(task), "gRecaptchaResponse")


def turnstile(site_key, page_url, use_proxy=True):
    task = {"websiteURL": page_url, "websiteKey": site_key}
    if use_proxy:
        task.update(type="TurnstileTask", **_proxy_fields())
    else:
        task["type"] = "TurnstileTaskProxyless"
    return _field(solve(task), "token")


def image(image_bytes):
    task = {"type": "ImageToTextTask", "body": base64.b64encode(image_bytes).decode()}
    return _field(solve(task), "text")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] in ("on", "off"):
        try:
            set_enabled(sys.argv[1] == "on")
        except CaptchaError as e:
            sys.exit(str(e))
    print("Captcha solving:", "ON" if is_enabled() else "OFF")
    try:
        print(f"Balance: ${float(balance()):.2f}")
    except CaptchaError as e:
        print("Balance: unavailable,", e)
