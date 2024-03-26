#!/bin/bash

install_debian() {
    sudo apt-get update
    sudo apt-get install -y automake libpcap-dev nfdump git python3-dev build-essential python3-venv
}

install_centos() {
    sudo dnf update -y
    sudo dnf install -y automake libpcap libpcap-devel nfdump git python3-devel build-essential python3-virtualenv
}

OS=$(awk -F= '/^NAME/{print $2}' /etc/os-release)

case $OS in
    *Ubuntu*|*Debian*)
        install_debian
        ;;
    *Fedora*|*Rocky*|*Alma*|*CentOS*|*RHEL*)
        install_centos
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "Installation complete."
