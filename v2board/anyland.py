import time
import requests

API_URL = "https://47.103.118.115:27018/"


def decrypt(enc):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    import base64
    key = b'apps_connect_key'
    iv = b'8c97f304422a60e0'
    ciphertext = base64.b64decode(enc)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()


def getUserInfo(userName, passWord):
    ts = str(time.time() * 1000)
    data = {
        "email": userName,
        "password": passWord,

    }
    with requests.post(
        url=f"{API_URL}api/v1/app/applogin?time={ts}",
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "android.v2board.app"
        },
        params=data,
    ) as response:
        if response.status_code == 200:
            body = response.json()
            # print(f'{yaml.dump(json.loads(decrypt(r.get("configsNodes"))), allow_unicode=True, sort_keys=False)}')
            print(f"{API_URL}api/v1/client/app/getConfig?token={body.get('token')}")
            return {
                "code": response.status_code,
                "subUrl": f"{API_URL}api/v1/client/app/getConfig?token={body.get('token')}",
                "v2ray": decrypt(body.get("configs")),
                'msg': "success"

            }
        elif response.status_code == 422:
            return {
                "code": response.status_code,
                "msg": response.json().get("errors"),
            }
        return {
            "code": response.status_code,
            "msg": "未知错误",
        }


if __name__ == "__main__":
    username = 'username'
    password = 'passwrod'
    getUserInfo(username, password)
