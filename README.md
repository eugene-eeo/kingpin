# kingpin

stateless SSH service for host-key automation.
example configuration:

```bash
# generate the CA key
ssh-keygen -f /tmp/ca -N ''
go build .
# start the service
./kingpin -addr localhost -ca /tmp/ca

# in another terminal
# from => 1 minute ago,
# to => 1 year.
token=$(curl -u admin:admin http://localhost:2222/token/ -d '{"from":-60,"to":31536000,"principals":["machine.fqdn","machine","10.0.0.1"]}' \
    | jq -r .token
)

# example of a "host" key --
# this can be automated via cloud-init, for example.
ssh-keygen -f /tmp/host -N ''
curl -H "X-Token: ${token}" -s http://localhost:2222/sign/ -d@/tmp/host.pub > /tmp/host.cert
# check the host key
ssh-keygen -L -f /tmp/host.cert | grep "$(ssh-keygen -l -f /tmp/ca.pub | awk '{print $2}')"
```