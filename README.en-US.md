# Sub2Clash

Extract configuration entry points from Android APKs or Clash/mihomo client files, decrypt app configurations, and log in to Xboard panels to retrieve Clash/Clash.Meta subscription content.

This project is intended solely for analyzing clients and subscription configurations that you have permission to use.

## Features

- Scan for configuration URLs from `lib/arm64-v8a/libapp.so` within an APK.
- Support identification and decryption of Xboard configurations:
  - `xboardV1`: `/apex/config.json`, base64 + XOR
  - `xboardV2`: `/oss/`, base64 + AES-CBC
  - `xboardV3`: Standard `.json`, base64 or plaintext JSON
- Log in to Xboard panels and output subscription request information and subscription content.
- Integrated `flclash` auxiliary workflows:
  - `.apk` calls `flclash/extract_mihomo_apk_aes.py`
  - `.pkg` calls `flclash/decrypt_mihomo_profile.py`

## Environment Requirements

- Python `>=3.14`
- Python dependencies can be found in [pyproject.toml](pyproject.toml)
- The Android APK AES extraction process requires `objdump` to be installed on the system.
- The macOS `.pkg`/Mach-O analysis process requires the following built-in macOS tools:
  - `otool`
  - `pkgutil`
  - `grep`

## Installation

Using `uv` is recommended:

```bash
uv sync
```

Alternatively, install dependencies via pip:

```bash
pip install requests pycryptodome pyyaml flask
```

## Quick Start

Edit [main.py](main.py) and fill in the account, password, and file path:

```python
if __name__ == '__main__':
    username = ''  # Enter email here
    password = ''  # Enter password here
    apk_path = "/path/to/app.apk"  # Enter path to APK or flclash-supported file
    run(username, password, apk_path)
```

Run:

```bash
python3 main.py
```

## Main Workflow Description

The entry point of `main.py` is:

```python
run(username, password, apk_path)
```

Execution flow:

1. If the passed file is not an `.apk`, it enters the `flclash` workflow directly based on the extension.
2. If it is an `.apk`, `getAppConfigUrl(apk_path)` is first called to scan for the configuration URL.
3. In the current `main.py`, if `len(config_url) == 3`, the `flclash` distribution logic is triggered.
4. The Xboard workflow decrypts the configuration to generate the `base_url`, `sub_url`, and request headers.
5. After logging into the panel, it requests the subscription interface and outputs the subscription link, request headers, and subscription content to the terminal.

Note: `getAppConfigUrl()` currently returns a dict containing three keys (`xboardV1`, `xboardV2`, `xboardV3`) by default, so `len(config_url) == 3` is usually always true for `.apk` files. If you want to prioritize standard Xboard configuration decryption, you should change the condition to "enter flclash only when no valid URL is found."

## Independent flclash Usage

### Extract mihomo AES Key/IV from Android APK

```bash
python3 flclash/extract_mihomo_apk_aes.py /path/to/app.apk
```

Default ABI check:

```text
arm64-v8a
```

Specify ABI:

```bash
python3 flclash/extract_mihomo_apk_aes.py /path/to/app.apk --abi arm64-v8a
```

This script extracts `lib/<abi>/libclash.so` from the APK, locates `metacubex/mihomo/common/convert.DecodeAESBase64`, and outputs the AES-128-CBC Key and IV.

### macOS `.pkg` or Mach-O Binary Extraction/Decryption

Extract Key/IV only:

```bash
python3 flclash/decrypt_mihomo_profile.py /path/to/client.pkg
```

Decrypt encrypted profile:

```bash
python3 flclash/decrypt_mihomo_profile.py /path/to/client.pkg /path/to/encrypted.yaml /path/to/output.yaml
```

Specify architecture:

```bash
python3 flclash/decrypt_mihomo_profile.py /path/to/client.pkg --arch arm64
```

Supports `x86_64` and `arm64`.

## Directory Structure

```text
.
├── main.py                         # Main entry point
├── core/
│   ├── ApkConfigUrlExtractor.py    # APK string scanning, config URL retrieval, decryption entry
│   ├── config.py                   # General request header processing
│   └── configCrypto.py             # AES/XOR/base64 decryption
├── xboard/
│   └── getinfo.py                  # Xboard login and subscription retrieval
├── flclash/
│   ├── extract_mihomo_apk_aes.py   # Android APK libclash.so AES Key/IV extraction
│   └── decrypt_mihomo_profile.py   # macOS mihomo profile decryption utility
└── demo/                           # Example scripts
```

## Troubleshooting

### `lib/arm64-v8a/libapp.so not found in APK`

The target APK does not contain `libapp.so` at that path. Verify the APK architecture and the actual .so filename, or modify `so_path` in `core/ApkConfigUrlExtractor.py`.

### `missing command: objdump`

The system cannot find `objdump` during the Android APK AES extraction process. Install binutils or ensure `objdump` is in your `PATH`.

### `mihomo convert DecodeAESBase64/aesDecryptCBC symbols were not found`

The target file may not be the corresponding mihomo/Clash.Meta fork, or the symbols have been stripped/obfuscated, making this process inapplicable.

### Login returns 403

This is usually because the request headers do not meet the server's requirements. Check the `app_name`, `customHeaders` decrypted from the config, and the current platform version branch.

## Disclaimer

Please only analyze clients, subscriptions, and server configurations that you own, maintain, or have authorization to use. Do not use this project for unauthorized access, bypassing payment restrictions, or infringing upon the rights of third parties.
