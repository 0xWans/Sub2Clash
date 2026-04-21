HEADERS = {
    'User-Agent': "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    'Accept-Encoding': "gzip"
}

from typing import Dict


def HeadersHandle(app_name: Any, custom_headers: list) -> Dict[str, str]:
    headers = {
        "user-agent": app_name
    }
    for item in custom_headers:
        if "key" in item and "value" in item:
            headers[item["key"]] = item["value"]
    return headers
