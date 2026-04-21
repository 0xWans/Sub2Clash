import requests


class Xboard:
    def __init__(self, username, password, base_url, sub_url: str, headers, plat):
        self.xboardUserSubInfo = None
        self.xboardUserInfo = None
        self.username = username
        self.password = password
        self.base_url = base_url
        self.sub_url = sub_url
        self.headers = headers
        self.loginData = None
        self.params = None
        self.flag = "meta"
        self.plat = plat

        self.session = requests.Session()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        self.session.close()

    def xboardLogin(self):
        headers = {
            **self.headers,
            "Content-Type": "application/json",
            "accept": "application/json"
        }
        fallback_url = None
        if self.plat == "xboardV1" or self.plat == "xboardV2":
            url = f"{self.base_url}/api/v1/passport/auth/login"
        elif self.plat == "xboardV3":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            del headers['accept']
            url = f"{self.base_url}/passport/auth/login"
            fallback_url = f"{self.base_url}/api/v1/passport/auth/login"
        else:
            print("没适配")
            exit(0)
        payload = {
            'email': self.username,
            'password': self.password,
        }

        with self.session.post(url=url, json=payload, headers=headers) as response:
            if self.plat == "xboardV3" and response.status_code == 404 and fallback_url:
                with self.session.post(url=fallback_url, json=payload, headers=headers) as fallback_response:
                    response = fallback_response

            print(f"状态码: {response.status_code}")
            print(response.text)
            if response.status_code == 200:
                self.loginData = response.json()
                self.params = {
                    "flag": self.flag,
                    "token": self.loginData.get('data').get('token')
                }
            elif response.status_code in (401, 400, 422):
                msg = response.json().get("message", "登录失败")
                raise RuntimeError(msg)
            elif response.status_code == 403:
                raise RuntimeError("请求头错误")
            else:
                raise RuntimeError(f"登录失败，状态码: {response.status_code}")

    def xboardGetUserSubInfo(self):
        with self.session.get(
            url=f"{self.base_url}/api/v1/user/getSubscribe",
            headers={
                **self.headers,
                "Content-Type": "application/json",
                "authorization": f"{self.loginData.get('data').get('auth_data')}"
            },
        ) as response:
            self.xboardUserSubInfo = response.json()

    def xboardGetSubData(self):
        print(f'\n登录API: {self.base_url}\n订阅API: {self.sub_url}\n平台版本: {self.plat}\n')
        print("登录中......")
        self.xboardLogin()
        print('登录成功！！！！！！')
        headers = {
            **self.headers,
            "Content-Type": "application/json",
        }
        print("获取订阅链接!!!!")
        if self.plat == "xboardV1":
            self.xboardGetUserSubInfo()
            self.sub_url = str(self.xboardUserSubInfo.get("data").get("subscribe_url"))
            with self.session.get(url=self.sub_url, headers=headers, params=self.params) as response:
                sub_status_code = response.status_code
                if sub_status_code != 200:
                    sub_data = "你买了吗？？？？"
                else:
                    sub_data = response.text
                    print(f"订阅链接: {response.request.url}")
                    print(f"请求头: {response.request.headers}")
        elif self.plat == "xboardV2":
            del headers['Content-Type']
            with self.session.get(url=self.sub_url + "/api/v1/client/subscribe", headers=headers, params=self.params) as response:
                sub_data = response.text
                print(f"订阅链接: {response.request.url}")
                print(f"请求头:")
                for k,v in response.request.headers.items():
                    print(f'"{k}": "{v}"')
        else:
            raise RuntimeError(f"不支持的平台: {self.plat}")
        print(f"""
订阅内容: 


{sub_data}
""")
