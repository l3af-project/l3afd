#!/bin/bash

# Start 'l3afd' in the background
/usr/local/l3afd/latest/l3afd --config /usr/local/l3afd/latest/l3afd.cfg &
sleep 5;

function check_and_wait() {
    sleep_time=$1
    while true; do
    if ps -p $(cat /var/run/l3afd.pid) > /dev/null; then
        sleep $sleep_time
    else
        break
    fi
    done
}

function on_term {
    echo "Signal $1 received"
    kill -SIGTERM  $(cat /var/run/l3afd.pid)
    check_and_wait 1
    echo "L3AFd process has terminated"
}

trap 'on_term SIGHUP' SIGHUP
trap 'on_term SIGINT' SIGINT
trap 'on_term SIGQUIT' SIGQUIT
trap 'on_term SIGTERM' SIGTERM
trap 'on_term SIGSTOP' SIGSTOP
trap 'on_term SIGSEGV' SIGSEGV
trap 'on_term SIGILL' SIGILL
trap 'on_term SIGKILL' SIGKILL
trap 'on_term SIGABRT' SIGABRT
trap 'on_term SIGBUS' SIGBUS

check_and_wait 5
