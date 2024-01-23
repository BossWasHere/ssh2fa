# SSH2FA

> SSH wrapper enabling password + two-factor authentication for SSH connections written in Python.

### Requirements

- pywinpty (Windows only)


### Example Usage

Connect to a host using a simple password:
```bash
$ python ssh2fa.py -i pp MyPassword user@host
```

Connect to a host using a plaintext password file and a two-factor authentication code:
```bash
$ python ssh2fa.py -i pf pass.txt -i op 123456 user@host
```

Connect to a host using an environment password variable and a TOTP code from a file:
```bash
$ python ssh2fa.py -i pe SSH_PASSWORD -i of totp.txt user@host
```

Connect to a host using a password, an OTP, and the same password again, without an interactive session:
```bash
$ python ssh2fa.py -i pf pass.txt -i of totp.txt -i rp 0 -x "-N -D 7777 user@host"
```

### Input Types
| Input Type          | Description                                        |
|----------------|----------------------------------------------------|
| `pp <PASS>`    | Plaintext password                                 |
| `pf <PATH>`    | Plaintext password file                            |
| `pe <ENV_VAR>` | Environment variable containing plaintext password |
| `op <OTP>`     | One-time password                                  |
| `oe <ENV_VAR>` | One-time password environment variable             |
| `of <PATH>`    | TOTP password file                                 |
| `oc <COMMAND>` | One-time password generating shell command         |
| `rp <INDEX>`   | Repeat input (from previously supplied inputs)     |
