#!/bin/bash

# @Author: detailyang
# @Date:   2016-09-20 15:09:14
# @Last Modified by:   detailyang
# @Last Modified time: 2016-10-10 14:57:20

while (( "$#" )); do
    case "$1" in
        --hostname|-h)
            hostname=$2
            shift
            ;;
        --dry|-d)
            dry=$2
            shift
            ;;
        --run|-r)
            run=$2
            shift
            ;;
        --show|-s)
            show=$2
            shift
            ;;
        --help)
cat <<EOS
usage: --hostname=localhost --run 1 or --hostname=localhost --dry 1
    --hostname|-h nginx hostname
    --dry|-d --dry 1 or --dry 0 set waf dry run or not
    --run|-r --run 1 or --run 0 set waf run mode or not
    --show show waf dashboard
    --help   see help
EOS
        exit 1
            ;;
    esac
    shift
done

#validation
vars=("hostname")
for var in "${vars[@]}"; do
    eval _var=\$$var
    if [[ -z "$_var" ]]; then
        echo "please set args: $var"
        exit 1
    fi
done

if [[ -z $dry ]] && [[ -z $run ]]; then
  curl -H "Host: bkb" http://$hostname/waf
else
  if [[ ! -z $dry ]]; then
    curl -H "Host: bkb" -X POST -d "dry=$dry" "http://$hostname/waf"
  fi
  if [[ ! -z $run ]]; then
    curl -H "Host: bkb" -X POST -d "run=$run" "http://$hostname/waf"
  fi
fi
