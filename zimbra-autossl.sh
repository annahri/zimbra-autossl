#!/bin/bash
set -o errexit
set -o errtrace
set -o pipefail

declare base_dir certs_dir caroot_dir domain_list renew_within email_address force_deploy
declare -a ca_roots
config_file="/etc/zimbra-autossl.conf"
cmd=$(basename "$0")

usage() {
    cat <<EOF
Usage: $cmd [option]

Auto Letsencrypt SSL setup for Zimbra instance. This script allows automated deployment of SSL
provided by LetsEncrypt.

Options:
  --deploy    Forces SSL certificate deployment.
              By default, if a certificate already issued by LE, the script will
              check the expiry date. If the days left (until expiry) doesn't meet
              the threshold yet, the script will exit. By setting this flag, the
              certificate will be deployed even if there's no new certificate issued.
  -h --help   Displays this info.
EOF

    exit
}

runas() { 
    args=( "$@" )
    su - zimbra -c "${args[@]}"
}

config_parser() {
    local config_file="$1" key value
    local -a array

    while IFS='=' read -r key value; do
        [[ -z "$key" || -z "$value" || "$key" =~ ^# ]] && continue

        key=$(awk '{$1=$1}1' <<< "$key")
        value=$(awk '{$1=$1}1' <<< "$value")
        value="${value%%#*}"

        if [[ "$value" =~ \[.*\] ]]; then
            # shellcheck disable=SC2001
            value="$(sed -r 's/^\[(.*)\]/\1/' <<< "$value")" 
            read -r -a array <<< "${value//,/ }"
            eval "$key=(${array[*]})"
            continue
        fi

        eval "$key=$value"
    done < "$config_file"
}

check_config() {
    if [[ -f "$config_file" ]]; then return; fi

    local -a domains

    echo "First time run. Please fill in the required values below."
    echo "Enter your email address for cert expiration alerts."
    read -r -p "Address: " email
    echo "This should be the directory where all the generated certs will be stored." 
    read -r -p "E.g /home/user/zimrba-autossl, /opt/zimbra-autossl : " artifacts_dir
    mkdir -p "${artifacts_dir%/}"

    cat <<EOF | tee "$config_file" > /dev/null
renew_within = 7 # days
email_address = "${email}"
base_dir = "${artifacts_dir%/}"

# Do not modify the below lines
certs_dir = "\${base_dir}/certs"
caroot_dir = "\${base_dir}/caroot"
domain_list = "\${base_dir}/ssldomains"

ca_roots = [ isrgrootx1, isrg-root-x2, lets-encrypt-r3 ]
EOF
    echo "Please enter the domain names (space separated)."
    read -a domains -r -p "The first domain would be the main domain: "

    printf '%s\n' "${domains[@]}" | tee "${artifacts_dir%/}/ssldomains"
}

check_dependencies() {
    if ! command -v certbot &> /dev/null; then
        echo "Certbot is required. Please install using:" >&2
        echo "  apt install certbot" >&2
        echo "    or" >&2
        echo "  dnf install certbot" >&2
        exit 3
    fi

    case "$(grep ID_LIKE /etc/os-release)" in
        *ubuntu*|*debian*)
            output=$(dpkg -l | grep 'python3-certbot-nginx' || true)
            # shellcheck disable=2181
            if [[ -z "$output" ]] ; then
                echo "This script requires python3-certbot-nginx plugin. Please install using:" >&2
                echo "  apt install python3-certbot-nginx" >&2
                exit
            fi
            ;;
        *rhel*)
            output=$(rpm -qa | grep 'python3-certbot-nginx' || true)
            if [[ -z "$output" ]]; then
                echo "This script requires python3-certbot-nginx plugin. Please install using:" >&2
                echo "  dnf install python3-certbot-nginx" >&2
                exit
            fi
            ;;
    esac
}

script_fail() {
    # This function will be executen when the script doesn't exit with 0
    # This will kill any non-zimbra nginx instances and start the zimbra ones
    echo "Auto SSL failed." >&2
    pgrep --full '/usr/sbin/ngin[x]' &> /dev/null && nginx -s quit
    runas "zmproxyctl start"
}

trap 'script_fail' ERR INT TERM

get_ca_roots() {
    # Check ca roots
    for ca in "${ca_roots[@]}"; do
        if [[ ! -f "${caroot_dir}/${ca}.pem" ]]; then
            curl -s --output "${caroot_dir}/${ca}.pem" "https://letsencrypt.org/certs/${ca}.pem"
        fi

        tee -a "${caroot_dir}/bundle.pem" < "${caroot_dir}/${ca}.pem" > /dev/null
    done

}

parse_args() {
    while [[ $# -ne 0 ]]; do case "$1" in
        -c|--config) config_file="${2:-$config_file}"; shift ;;
        -d|--deploy) force_deploy=1 ;;
        -h|--help) usage ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac; shift; done
}

main() {
    parse_args "$@"

    if [[ $EUID -ne 0 ]]; then
        echo "This script needs to be run as root." >&2
        exit
    fi

    check_dependencies
    check_config
    config_parser "$config_file"

    mkdir -p "$base_dir" "$certs_dir" "$caroot_dir"

    if [[ ! -f "$domain_list" ]]; then
        echo "$domain_list file doesn't exist." >&2
        exit 1
    fi

    if [[ ! -s "$domain_list" ]]; then
        echo "Domains cannot be empty." >&2
        echo "Please fill the $domain_list, with the domain list." >&2
        echo "The first line is going to be the main domain." >&2
        exit 2
    fi

    # Retrieve domain list
    readarray -t ssl_domains < "$domain_list"

    # Construct args for certbot
    readarray -t certbot_args < <(printf -- '-d %s\n' "${ssl_domains[@]}")

    letsencrypt_dir="/etc/letsencrypt/live/${ssl_domains[0]}"
    zimbra_ssl_dir="/opt/zimbra/ssl/${ssl_domains[0]}"
    mkdir -p "$zimbra_ssl_dir"

    if [[ -d "$letsencrypt_dir" && -z "$force_deploy" ]]; then
        days_left="$(certbot certificates 2> /dev/null | grep -A1 "Domains: ${ssl_domains[0]}" | grep VALID | sed 's/.*(VALID: \(.*\) days.*/\1/')"

        if [[ $days_left -gt $renew_within ]]; then
            echo "Certificate is not within renewal days ($renew_within days before expiration). Exit" >&2
            exit 0
        fi
    fi

    # Temporarily stop Zimbra Nginx instance
    echo "Stopping Zimbra Proxy temporarily..."
    runas 'zmproxyctl stop'

    # Retrieve the certs
    echo "Retrieving certificates..."
    certbot certonly --nginx -q -n \
        --agree-tos --email "$email_address" \
        --expand --cert-name "${ssl_domains[0]}" \
        "${certbot_args[@]}"

    echo "Generating CA bundle..."
    get_ca_roots

    # Create Certificate bundle
    echo "Creating certificate bundle..."
    cat "${letsencrypt_dir}/cert.pem" "${caroot_dir}/bundle.pem" > "${zimbra_ssl_dir}/bundle.pem"

    # Copy the certs to Zimbra dir
    install --owner zimbra --group zimbra --preserve-timestamps \
        "${letsencrypt_dir}/cert.pem" \
        "${zimbra_ssl_dir}/cert.pem"
    install --owner zimbra --group zimbra --preserve-timestamps \
        "${letsencrypt_dir}/privkey.pem" \
        "${zimbra_ssl_dir}/privkey.pem"

    # Do certs verification
    echo "Verifying the certificate files..."
    runas "zmcertmgr verifycrt comm \
        '${zimbra_ssl_dir}/privkey.pem' \
        '${zimbra_ssl_dir}/bundle.pem' \
        '${caroot_dir}/bundle.pem'" &> /dev/null

    # Overwrite the default comm privkey with the LE ones
    install --owner zimbra --group zimbra --preserve-timestamps \
        "${letsencrypt_dir}/privkey.pem" \
        "/opt/zimbra/ssl/zimbra/commercial/commercial.key"

    # Deploy the certs
    echo "Deploying certificates..."
    runas "zmcertmgr deploycrt comm \
        '${zimbra_ssl_dir}/bundle.pem' \
        '${caroot_dir}/bundle.pem'" &> /dev/null

    # Stop any lingering nginx processes
    echo "Killing remaining nginx processes..."
    pgrep --full '/usr/sbin/ngin[x]' &> /dev/null \
        && nginx -s quit

    # Restart all zimbra services to apply the new certs
    echo "Restarting Zimbra services..."
    runas "zmcontrol restart" &> /dev/null

    echo "Done"
    trap -- ERR
}

main "$@"
