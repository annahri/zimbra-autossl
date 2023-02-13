# Zimbra Auto SSL

Usage:

```plain
Usage: zimbra-autossl.sh [option]

Auto Letsencrypt SSL setup for Zimbra instance. This script allows automated deployment of SSL
provided by LetsEncrypt.

Options:
  --deploy    Forces SSL certificate deployment.
              By default, if a certificate already issued by LE, the script will
              check the expiry date. If the days left (until expiry) doesn't meet
              the threshold yet, the script will exit. By setting this flag, the
              certificate will be deployed even if there's no new certificate issued.
  -h --help   Displays this info.
```

# To do

- [ ] Better logging
- [ ] Add a spinner?
- [ ] ..
