from pathlib import Path

from core.ApkConfigUrlExtractor import getAppConfigUrl, getAppConfigData
from core.config import HeadersHandle, HEADERS
from flclash import decrypt_mihomo_profile, extract_mihomo_apk_aes
from xboard.getinfo import Xboard


FLCLASH_HANDLERS = {
    ".apk": extract_mihomo_apk_aes.main,
    ".pkg": decrypt_mihomo_profile.main,
}


def run_flclash_by_suffix(file_path: str) -> None:
    suffix = Path(file_path).suffix.lower()
    handler = FLCLASH_HANDLERS.get(suffix)
    if handler is None:
        support_suffixes = ", ".join(sorted(FLCLASH_HANDLERS))
        raise ValueError(f"flclash暂不支持该文件后缀: {suffix or '<无后缀>'}，支持: {support_suffixes}")
    handler([file_path])


def run(username: str, password: str, apk_path: str) -> None:
    if Path(apk_path).suffix.lower() != ".apk":
        print("匹配到flclash处理流程......")
        try:
            run_flclash_by_suffix(apk_path)
        except (extract_mihomo_apk_aes.Die, decrypt_mihomo_profile.Die, ValueError) as e:
            print(f"flclash处理失败: {e}")
        return

    # 获取配置文件的url
    print("获取登录的接口......")
    config_url = getAppConfigUrl(apk_path)
    print(config_url)
    if len(config_url) == 3:
        print("匹配到flclash处理流程......")
        try:
            run_flclash_by_suffix(apk_path)
        except (extract_mihomo_apk_aes.Die, decrypt_mihomo_profile.Die, ValueError) as e:
            print(f"flclash处理失败: {e}")
        return
    # 配置文件的数据
    print("解密配置文件......")
    data = getAppConfigData(config_url)
    app_data = data.get('data')
    app_name = data.get('appname')
    plat = data.get('plat')
    base_url, sub_url, headers = None, None, None
    if plat == "xboardV1":
        headers = {
            **HEADERS,
            'User-Agent': app_name
        }
        base_url = app_data.get("domains")[0]
        sub_url = app_data.get("domains")[0]
    elif plat == "xboardV2":
        headers = HeadersHandle(app_name, app_data.get('customHeaders'))
        base_url = app_data.get('apiSettings').get('urls')[0].get('url')
        sub_url = app_data.get('apiSettings').get('subscriptionUrls')[0]
    elif plat == "xboardV3":
        headers = {
            **HEADERS,
            'User-Agent': app_name
        }
        base_url = app_data.get('hosts')[0]
        sub_url = app_data.get('hosts')[0]
    else:
        print("什么都没找到......")
        exit(0)
    with Xboard(username=username, password=password, base_url=base_url, sub_url=sub_url, headers=headers,
                plat=plat) as xboard:
        xboard.xboardGetSubData()


if __name__ == '__main__':
    username = ''  # 这里填邮箱
    password = ''  # 这里填密码
    apk_path = "/Volumes/Data/Downloads/yytapp-lite.apk"  # 这里填apk的路径
    run(username, password, apk_path)
