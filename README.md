# CertCheckerApple
tells you if the .p12 certificate you gave it is revoked or not.

`uses apple oscp to check if cert is revoked or not.`
`Legacy cert support is automatically enabled. if you don't know what this means, ignore it.`

---

## `Dependencies`
```bash
# i think this is all, i forgot after so many runs
# btw, u need openssl in path
# if openssl -v doesn't work, check how to install for ur OS
# for linux it depends on distro. mine was sudo pacman -Sy OpenSSL
pip install cryptography requests
```
## ``Usage``
``
python3 check.py cert.p12 pass
``

* You could use this as an API

**Output 1 (VALID CERT)**:

```json
{
  "Status": "VALID",
  "ValidUntil": "2025-09-01T23:59:59+00:00",
  "ValidFor": "39 days from now"
}
```

**Output 2 (REVOKED CERT)**:
```json
{
  "Status": "REVOKED",
  "RevokedAt": "2024-11-30T17:08:54+00:00",
  "ProducedAt": "2025-07-24T14:01:12+00:00",
  "RevokedSince": "236 days ago"
}
```

* All you really need is the ``Status`` key value.
