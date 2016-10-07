#!/bin/bash

# @Author: detailyang
# @Date:   2016-09-20 15:09:14
# @Last Modified by:   detailyang
# @Last Modified time: 2016-09-20 15:36:11

while (( "$#" )); do
    case "$1" in
        --hostname|-h)
            hostname=$2
            shift
            ;;
        --type|-t)
            type=$2
            case "$type" in
                ip|rule)
                ;;
                *)
                    echo "type only support ip|rule"
                    exit 0
                    ;;
            esac
            shift
            ;;
        --help)
cat <<EOS
usage: --hostname localhost --type ip|rule
    --hostname nginx hostname
    --type ip|rule
    --help   see help
EOS
        exit 1
            ;;
    esac
    shift
done

#validation
vars=("hostname" "type")
for var in "${vars[@]}"; do
    eval _var=\$$var
    if [[ -z "$_var" ]]; then
        echo "please set args: $var"
        exit 1
    fi
done

case "$type" in
    ip)
        curl -H "Host: bkb" -X PUT "http://$hostname/$type"
        ;;
    rule)
        curl -H "Host: bkb" -X PUT "http://$hostname/$type"
        ;;
esac
