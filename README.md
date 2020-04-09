![ProHacktive](https://prohacktive.io/storage/parameters_images/LmQm4xddzmyFAdGYvQ32oZ9t1P9e8098UubYjnE9.svg "uPKI from ProHacktive.io")

# µPKI
***NOT READY FOR PRODUCTION USE***
This project has only been tested on Debian 9 Strech with Python3.6.
Due to python usage it *SHOULD* works on many other configurations, but it has NOT been tested.

## 1. About
µPki [maɪkroʊ ˈpiː-ˈkeɪ-ˈaɪ] is a small PKI in python that should let you make basic tasks without effort.
It works in combination with:
> - [µPKI-RA](https://github.com/proh4cktive/upki-ra)
> - [µPKI-WEB](https://github.com/proh4cktive/upki-web)
> - [µPKI-CLI](https://github.com/proh4cktive/upki-cli)

µPki is the Certification Authority that is invoked by the [µPKI-RA](https://github.com/proh4cktive/upki-ra) Registration Authority.

### 1.1 Dependencies
The following modules are required
- PyMongo
- Cryptography
- Validators
- TinyDB
- PyYAML
- PyZMQ

Some systems libs & tools are also required, make sure you have them pre-installed
```bash
sudo apt update
sudo apt -y install build-essential libssl-dev libffi-dev python3-dev python3-pip git
```

## 2. Install
The Installation process require two different phases:

1. clone the current repository
```bash
git clone https://github.com/proh4cktive/upki
cd ./upki
```

2. Install the dependencies and upki-ca service in order to auto-start service on boot if needed. The install script will also guide you during the setup process of your Registration Authority (RA).
```bash
./install.sh
```

If you plan to use two different servers for CA & RA (recommended) you can specify on which ip:port your CA should listen.
```bash
./install.sh -i 127.0.0.1 -p 5000
```

## 3. Usage
The Certification Authority (CA) is not designed to be handled manually. Always use the Registration Authority (RA) in order to manage profile and certificates.

If needed you can still check options using
```bash
./ca_server.py --help
```

## 3.1 RA registration
Certification Authority can not run alone, you MUST setup a Registration Authority to manage certificate. *The current process generates a specific RA certificate in order to encrypt the communication between CA and RA in near future, but this is not currently set!*
Start the CA in register mode in order to generate a one-time seed value that you will have to reflect on your RA start
```bash
./ca_server.py register
```

## 3.2 Common usage
Once your RA registered you can simply launch your service by calling 'listen' action. This is basically what the services is doing.
```bash
./ca_server.py listen
```

## 4. Advanced usage
If you know what you are doing, some more advanced options allows you to setup a specific CA/RA couple.

### 4.1 Change default directory
If you want to change the default directory path ($HOME/.upki) for logs, config and storage, please use the 'path' flag
```bash
./ca_server.py --path /my/new/directory/
```

If you want to change only log directory you can use the 'log' flag.
```bash
./ca_server.py --log /my/new/log/directory/
```

### 4.2 Import existing CA keychain
If you already have a CA private key and certificate you can import them, by putting PEM encoded:
    . Private Key (.key file)
    . optionnal Certificate Request (.csr file)
    . Public Certificate (.crt file)
All in same directory and call
```bash
./ca_server.py init --ca /my/ca/files/
```

### 4.3 Listening IP:Port
In order to deploy for more serious purpose than just testing, you'll probably ended up with a different server for your RA. You must then specify an IP and a port that will must be reflected in your RA configuration.

For RA registration:
```bash
./ca_server register --ip X.X.X.X --port 5000
```

For common operations
```bash
./ca_server listen --ip X.X.X.X --port 5000
```

## 5. Help
For more advanced usage please check the app help global
```bash
./ca_server.py --help
```

You can also have specific help for each actions
```bash
./ca_server.py init --help
```

## 4. TODO
Until being ready for production some tasks remains:
> - Setup Unit Tests
> - Refactoring of Authority class
> - Refactoring of Storage classes (FileStorage)
> - Add support for MongoDB and PostgreSQL
> - Setup ZMQ-TLS encryption between CA and RA
> - Setup an intermediate CA in order to sign CSR, and preserve original key file (best-practices)
> - Add uninstall.sh script
