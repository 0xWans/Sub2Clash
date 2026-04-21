import zipfile
import re
from typing import List, Dict, Any

import requests

from core.config import HEADERS
from core.configCrypto import decrypt_base64_aes, decrypt_base64_xor, base64_decode

URL_REGEX = re.compile(
    r'https?://[a-zA-Z0-9./?&=_\-:%]+'
)

def extract_strings(data: bytes, min_len=4) -> List[str]:
    result = []
    buf = bytearray()
    for b in data:
        if 32 <= b <= 126:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                result.append(buf.decode(errors="ignore"))
            buf = bytearray()
    if len(buf) >= min_len:
        result.append(buf.decode(errors="ignore"))
    return result


def testUrl(url: str, timeout: int = 5) -> bool:
    """
    判断 URL 是否可访问
    返回：
        True  -> 可访问（状态码 200~399）
        False -> 不可访问
    """
    try:
        # 先用 HEAD（更快）
        with requests.head(url, headers=HEADERS, timeout=timeout, allow_redirects=True) as resp:
            if 200 <= resp.status_code < 400:
                return True
        # 有些服务器不支持 HEAD，fallback 到 GET
        with requests.get(url, headers=HEADERS, timeout=timeout, stream=True) as resp:
            return 200 <= resp.status_code < 400
    except requests.RequestException:
        return False


def getAppConfigUrl(apk_path: str) -> Dict[str, List]:
    so_path = "lib/arm64-v8a/libapp.so"
    with zipfile.ZipFile(apk_path, 'r') as z:
        if so_path not in z.namelist():
            raise FileNotFoundError(f"{so_path} not found in APK")
        data_bytes = z.read(so_path)
    strings = extract_strings(data_bytes)
    configUrlsV1,configUrlsV2,configUrlsV3 = set(),set(),set()
    for s in strings:
        for u in URL_REGEX.findall(s):
            if "/apex/config.json" in u and testUrl(u):
                configUrlsV1.add(u)
            elif "/oss/" in u and testUrl(u):
                configUrlsV2.add(u)
            elif ".json" in u and testUrl(u) and "update.json" not in u:
                configUrlsV3.add(u)
    return {
        "xboardV1": list(configUrlsV1),
        "xboardV2": list(configUrlsV2),
        "xboardV3": list(configUrlsV3)
    }


def getAppConfigData(app_hex_url: Dict) -> Dict[str, Any]:
    """
    :param app_hex_url:
    :return:  {
        'app_name': app_name,
        'data': data, # 数据，主要是app的配置
        'plat': plat # 平台
    }
    """
    de_data, app_name, plat = None, "Mozilla/5.0 (dart:io) SuperAccelerator", None
    for key, value in app_hex_url.items():
        if key == "xboardV1" and value:
            with requests.get(url=str(value[0]), headers=HEADERS) as resp:
                de_data = decrypt_base64_xor(resp.text)
                plat = key
        elif key == "xboardV2" and value:
            with requests.get(value[0], headers=HEADERS) as resp:
                de_data = decrypt_base64_aes(resp.text)
                app_name = resp.request.url.split("/")[-1]
                plat = key
        elif key == "xboardV3" and value:
            with requests.get(value[0], headers=HEADERS) as resp:
                de_data = base64_decode(resp.text)
                plat = key

    return {'appname': app_name, 'data': de_data, "plat": plat}



