#!/bin/sh

function doCurl() {
    echo "http://127.0.0.1:5000/portalserver/$1"
    curl -G  "http://127.0.0.1:5000/portalserver/$1"
}

other() {
    echo "Usage: $0 {start|stop|list}"
}

case "$1" in
    start)
        doCurl "login?username=$2&password=$4&brasip=$3&userip=192.168.1.5"
        ;;
    stop)
        doCurl  "logout?username=$2&brasip=$3"
        ;;
    list)
        doCurl  "getvlaninfo?username=$2&brasip=$3"
        ;;
    *)
        other
        ;;
esac
