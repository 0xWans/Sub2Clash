# Sub2Clash

从 Android APK 或 Clash/mihomo 客户端文件中提取配置入口，解密应用配置，并登录 Xboard 面板获取 Clash/Clash.Meta 订阅内容。

本项目仅用于分析你有权限使用的客户端和订阅配置。

## 功能

- 从 APK 的 `lib/arm64-v8a/libapp.so` 中扫描配置 URL。
- 支持识别并解密 Xboard 配置：
  - `xboardV1`: `/apex/config.json`，base64 + XOR
  - `xboardV2`: `/oss/`，base64 + AES-CBC
  - `xboardV3`: 普通 `.json`，base64 或明文 JSON
- 登录 Xboard 面板并输出订阅请求信息和订阅内容。
- 集成 `flclash` 辅助流程：
  - `.apk` 调用 `flclash/extract_mihomo_apk_aes.py`
  - `.pkg` 调用 `flclash/decrypt_mihomo_profile.py`

## 环境要求

- Python `>=3.14`
- Python 依赖见 [pyproject.toml](pyproject.toml)
- Android APK AES 提取流程需要系统有 `objdump`
- macOS `.pkg`/Mach-O 分析流程需要 macOS 自带工具：
  - `otool`
  - `pkgutil`
  - `grep`

## 安装

推荐使用 `uv`：

```bash
uv sync
```

或使用 pip 安装依赖：

```bash
pip install requests pycryptodome pyyaml flask
```

## 快速使用

编辑 [main.py](main.py)，填写账号、密码和文件路径：

```python
if __name__ == '__main__':
    username = ''  # 这里填邮箱
    password = ''  # 这里填密码
    apk_path = "/path/to/app.apk"  # 这里填 APK 或 flclash 支持的文件路径
    run(username, password, apk_path)
```

运行：

```bash
python3 main.py
```

## 主流程说明

`main.py` 的入口是：

```python
run(username, password, apk_path)
```

执行流程：

1. 如果传入的文件不是 `.apk`，直接根据后缀进入 `flclash` 流程。
2. 如果是 `.apk`，先调用 `getAppConfigUrl(apk_path)` 扫描配置 URL。
3. 当前 `main.py` 中 `len(config_url) == 3` 时会进入 `flclash` 分发逻辑。
4. Xboard 流程会解密配置，生成 `base_url`、`sub_url` 和请求头。
5. 登录面板后请求订阅接口，并在终端输出订阅链接、请求头和订阅内容。

注意：`getAppConfigUrl()` 当前固定返回包含 `xboardV1`、`xboardV2`、`xboardV3` 三个 key 的 dict，因此 `len(config_url) == 3` 对 `.apk` 通常会一直成立。如果要优先走普通 Xboard 配置解密，需要把判断条件改成“没有找到有效 URL 时再进入 flclash”。

## flclash 独立用法

### Android APK 提取 mihomo AES Key/IV

```bash
python3 flclash/extract_mihomo_apk_aes.py /path/to/app.apk
```

默认检查 ABI：

```text
arm64-v8a
```

指定 ABI：

```bash
python3 flclash/extract_mihomo_apk_aes.py /path/to/app.apk --abi arm64-v8a
```

该脚本会从 APK 中提取 `lib/<abi>/libclash.so`，定位 `metacubex/mihomo/common/convert.DecodeAESBase64`，并输出 AES-128-CBC 的 Key 和 IV。

### macOS `.pkg` 或 Mach-O 二进制提取/解密

只提取 Key/IV：

```bash
python3 flclash/decrypt_mihomo_profile.py /path/to/client.pkg
```

解密加密 profile：

```bash
python3 flclash/decrypt_mihomo_profile.py /path/to/client.pkg /path/to/encrypted.yaml /path/to/output.yaml
```

指定架构：

```bash
python3 flclash/decrypt_mihomo_profile.py /path/to/client.pkg --arch arm64
```

支持 `x86_64` 和 `arm64`。

## 目录结构

```text
.
├── main.py                         # 主入口
├── core/
│   ├── ApkConfigUrlExtractor.py    # APK 字符串扫描、配置 URL 获取、配置解密入口
│   ├── config.py                   # 通用请求头处理
│   └── configCrypto.py             # AES/XOR/base64 解密
├── xboard/
│   └── getinfo.py                  # Xboard 登录和订阅获取
├── flclash/
│   ├── extract_mihomo_apk_aes.py   # Android APK libclash.so AES Key/IV 提取
│   └── decrypt_mihomo_profile.py   # macOS mihomo profile 解密辅助
└── demo/                           # 示例脚本
```

## 常见问题

### `lib/arm64-v8a/libapp.so not found in APK`

目标 APK 中没有该路径的 `libapp.so`。需要确认 APK 架构和实际 so 文件名，或改造 `core/ApkConfigUrlExtractor.py` 中的 `so_path`。

### `missing command: objdump`

运行 Android APK AES 提取流程时系统找不到 `objdump`。安装 binutils，或确保 `objdump` 在 `PATH` 中。

### `mihomo convert DecodeAESBase64/aesDecryptCBC symbols were not found`

目标文件可能不是对应的 mihomo/Clash.Meta fork，或符号已被裁剪/混淆，此流程不适用。

### 登录返回 403

通常是请求头不符合服务端要求。检查配置解密出的 `app_name`、`customHeaders` 和当前平台版本分支。

## 免责声明

请仅分析自己拥有、维护或已获得授权的客户端、订阅和服务端配置。不要将本项目用于未授权访问、绕过付费限制或侵犯第三方权益。
