# SNI-Spoofing

Bypass DPI with IP/TCP-header manipulation.

## Termux / Android support

`pydivert` uses the Windows-only WinDivert driver and DLLs. Android/Termux cannot
load WinDivert, so the app now starts without importing `pydivert` unless the
Windows packet-injection backend is actually enabled.

On Termux the program automatically falls back to `INJECTOR_BACKEND=none` style
behavior and disables packet spoofing. This makes the proxy runnable on Android,
but it is **not the same as the original `wrong_seq` packet injection**. Real
`wrong_seq` spoofing still requires Windows with WinDivert/pydivert, or a
separate Android raw-packet implementation that is not included here.

### Install on Termux

```bash
pkg update
pkg install python
python -m pip install -r requirements.txt
python main.py
```

`requirements.txt` only installs `pydivert` on Windows, so Termux will not try to
build or load Windows DLL dependencies.

### Configuration

`config.json` supports these keys:

- `LISTEN_HOST` / `LISTEN_PORT`: local TCP listener.
- `CONNECT_IP` / `CONNECT_PORT`: remote server to connect to.
- `FAKE_SNI`: hostname used in the generated fake TLS ClientHello.
- `DATA_MODE`: currently `tls`.
- `BYPASS_METHOD`:
  - `wrong_seq`: original WinDivert packet-injection mode on Windows. On
    non-Windows platforms with `INJECTOR_BACKEND=auto`, this safely falls back to
    `none`.
  - `none`: do not send spoofed packets; just run the TCP relay. Recommended for
    Termux because Android cannot use WinDivert.
  - `direct`: send the generated fake TLS ClientHello as normal TCP data. This is
    experimental and can break normal TLS clients because the server receives the
    fake ClientHello as real traffic.
- `INJECTOR_BACKEND`:
  - `auto`: use pydivert only on Windows, otherwise no packet injector.
  - `pydivert`: force WinDivert/pydivert. Use this only on Windows.
  - `none`: never import or start pydivert. Recommended for Termux.
- `INTERFACE_IPV4` (optional): override the detected source IPv4 address.

For Termux you can explicitly set:

```json
{
  "BYPASS_METHOD": "none",
  "INJECTOR_BACKEND": "none"
}
```

## Windows packet-injection mode

Install WinDivert and run with `INJECTOR_BACKEND=auto` or `pydivert`. The original
`wrong_seq` behavior is still available there.

## Original project notes

حمایت کنید کارهای بزرگی در دست انجام هست:

USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424

USDT (TRC20): TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o

https://t.me/projectXhttp

https://t.me/patterniha
