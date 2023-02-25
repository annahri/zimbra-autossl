# Zimbra Auto SSL

A simple script that automatically fetches LetsEncrypt SSL and install them to your Zimbra Instance.

## Usage

```plain
Usage: zimbra-autossl.sh [option]

Auto LetsEncrypt SSL setup for Zimbra instance.
This script allows automated deployment of SSL provided by LetsEncrypt using cronjob.

A config file will be generated in /etc/zimbra-autossl/config upon executing for the first time.

If you want to add more domains, please edit the ssldomains file.

Options:
  -c --cron   
    Disables spinner and enter non-interactive mode.
  -C --certsonly
    Only do certificate request.
  -d --deploy 
    Forces SSL certificate deployment.
    By default, if a certificate already issued by LE, the script will
    check the expiry date. If the days left (until expiry) doesn't meet
    the threshold yet, the script will exit. By setting this flag, the
    certificate will be deployed even if there's no new certificate issued.

  -h --help   
    Displays this info.

Info:

Option -C|--certsonly and -d|--deploy, cannot be set together. The latter will unset the precedent.
Example: `zimbra-autossl.sh -C -d` => The -C option will be disregarded. And vice-versa.
```
On the first execution, the script will prompt you for some required data. Then it will be stored on a config file in `/etc/zimbra-autossl/config`

Sample config file:

```plain
renew_within = 7 # days
email_address = "email@domain.tld"
base_dir = "/etc/zimbra-autossl"

# Do not the preceeding variable '${base_dir}'
certs_dir = "${base_dir}/certs"
caroot_dir = "${base_dir}/caroot"
domain_list = "${base_dir}/ssldomains"

ca_roots = [ isrgrootx1, isrg-root-x2, lets-encrypt-r3 ]
```

Demo:

```
root@zm1:~# ./zimbra-autossl.sh --deploy
[✓] Stopping Zimbra Proxy temporarily
[✓] Retrieving certificates
[✓] Generating CA bundle
[✓] Creating certificate bundle
[✓] Verifying the certificate files
[✓] Deploying certificates
[✓] Killing remaining nginx processes
[✓] Restarting Zimbra services
All is done!
```

## To do

- [ ] Better dependency checking
- [ ] Better config parsing
- [ ] Better wording
- [x] Add a spinner?
- [ ] ..
