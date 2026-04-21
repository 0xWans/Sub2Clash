from core.ApkConfigUrlExtractor import getAppConfigUrl, getAppConfigData
from core.config import HeadersHandle, HEADERS
from xboard.getinfo import Xboard


def run(username: str, password: str, apk_path: str) -> None:
    # 获取配置文件的url
    print("获取登录的接口......")
    config_url = getAppConfigUrl(apk_path)
    print(config_url)
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
    username = '@gmail.com' # 这里填邮箱
    password = '123456' # 这里填密码
    apk_path = "/your/path/1.apk"   # 这里填apk的路径
    run(username, password, apk_path)
