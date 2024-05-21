# ssh-helper

Simple helper that can be used as the AuthorizedPrincipalsCommand
for [sshd_config(5)](https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommand). Inspired by [teleport](https://goteleport.com).
Configuration is done in 2 parts, SSHD:

```
# /etc/ssh/sshd_config.d/99-my.conf
AuthorizedPrincipalsCommand /usr/local/bin/ssh-helper -base64-cert %k
AuthorizedPrincipalsCommandUser nobody
# highly recommended
TrustedUserCAKeys ...
```

configuration file, `/etc/no.cloud/machine.json`:

```json
{
    "machine": "hostname.fqdn.io",
    "allowed_logins": [":any"],
    "labels": {
        "foo": "bar"
    }
}
```

then a user certificate created in any of these ways can be used to login as
_any_ (from the `:any` stanza) user on the machine:

1. Directly referencing the machine
   ```sh
   ssh-keygen -u -s ./ssh/ca \
      -n USER \
      -O 'extension:machine@no.cloud=hostname.fqdn.io' \
      -I 'key comment' \
      PUBKEY
   ```
   You can also use a comma separated list, or `*` to allow all.

2. Using labels:
   ```sh
   ssh-keygen -u -s ./ssh/ca \
      -n USER \
      -O 'extension:labels@no.cloud=foo=bar' \
      -I 'key comment' \
      PUBKEY
   ```

3. Multiple _sets_ of labels:
   ```sh
   ssh-keygen -u -s ./ssh/ca \
      -n USER \
      -O 'extension:labels-1@no.cloud=foo=bar' \
      -O 'extension:labels-2@no.cloud=foo=baz,boo=gaz' \
      -I 'key comment' \
      PUBKEY
   ```
   an individual label set is ANDed (everything must match),
   whilst multiple label sets are ORed.
