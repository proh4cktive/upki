#!/bin/bash

echo -e "\t\t..:: µPki Certification Authority Installer ::.."
echo ""

# If user is not root, try sudo
if [[ $EUID -ne 0 ]]; then
    sudo -p "Enter your password: " whoami 1>/dev/null 2>/dev/null
    if [ ! $? = 0 ]; then 
        echo "You entered an invalid password or you are not an admin/sudoer user. Script aborted."
        exit 1
    fi
fi

# Setup user vars
USERNAME=${USER}
GROUPNAME=$(id -gn $USER)
INSTALL=${PWD}

# Setup UPKI default vars
UPKI_DIR="${HOME}/.upki/"
UPKI_IP='127.0.0.1'
UPKI_PORT=5000

usage="$(basename "$0") [-h] [-i ${UPKI_IP}] [-p ${UPKI_PORT}] -- Install script for uPKI Certification Authority

where:
    -h  show this help text
    -i  set the CA listening IP (default: 127.0.0.1)
    -p  set the CA listening port (default: 5000)
"

while getopts ':hip:' option; do
  case "$option" in
    h) echo "$usage"
       exit
       ;;
    i) UPKI_IP=$OPTARG
       ;;
    p) UPKI_PORT=$OPTARG
       ;;
    :) printf "missing argument for -%s\n" "$OPTARG" >&2
       echo "$usage" >&2
       exit 1
       ;;
   \?) printf "illegal option: -%s\n" "$OPTARG" >&2
       echo "$usage" >&2
       exit 1
       ;;
  esac
done
shift $((OPTIND - 1))

# Update system & install required apps
echo "[+] Update system"
sudo apt -y update && sudo apt -y upgrade
echo "[+] Install required apps"
sudo apt -y install build-essential libssl-dev libffi-dev python3-dev python3-pip git

# Install required libs
echo "[+] Install required libs"
pip3 install -r requirements.txt

# First run init step
./ca_server.py --path ${UPKI_DIR} init

# Create ca service
echo "[+] Create services"
sudo tee /etc/systemd/system/upki.service > /dev/null <<EOT
[Unit]
Description=µPki Certification Authority service
ConditionACPower=true
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USERNAME}
Group=${GROUPNAME}
Restart=always
ExecStart=${INSTALL}/ca_server.py --path ${UPKI_DIR} listen --ip ${UPKI_IP} --port ${UPKI_PORT}

[Install]
WantedBy=multi-user.target
EOT

# Reload services
sudo systemctl daemon-reload

# Then run register step
./ca_server.py --path ${UPKI_DIR} register --ip ${UPKI_IP} --port ${UPKI_PORT}

echo "Do you wish to activate uPKI service on boot?"
select yn in "Yes" "No"; do
    case $yn in
        Yes )
            # Start uPKI service
            echo "[+] Activate service"
            sudo systemctl enable upki.service
            sudo service upki start
            break;;
        No ) exit;;
    esac
done

echo "[+] All done"
echo ""
