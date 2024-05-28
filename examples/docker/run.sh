#!/bin/bash
# VERSION:
#  dev - development branch, often updated, might not be working version
#  latest - stable working version

# Check if parameters are defined. If not, print usage and exit 1.
if [ $# == 0 ]; then
    echo "Usage: `basename $0` [-i imagetag] [-n networkmode]"
    echo "  -i imagetag (MANDATORY)"
    echo "     specify image tag, e.g. latest, dev, v1.3.0... For production deplyoment use latest, unless instructed otherwise by SENSE team"
    echo "  -n networkmode (OPTIONAL). Default port mode"
    echo "     specify network mode. One of: host,port."
    echo "     host means it will use --net host for docker startup. Please make sure to open port 80, 443 in firewall. Use this option only if any of your hosts, network devices are IPv6 only (no IPv4 address)."
    echo "     port means it will use -p 8080:80 -p 8443:443 in docker startup. Docker will open port on system firewall. Default parameter"
    exit 1
fi

RED='\033[0;31m'
NC='\033[0m' # No Color

certchecker () {
  local ERROR=false
  cdata=`openssl x509 -in $1 -pubkey -noout -outform pem`
  cexitcode=$?
  kdata=`openssl pkey -in $2 -pubout -outform pem`
  kexitcode=$?
  if [ $cexitcode != 0 ] || [ $kexitcode != 0 ]; then
    echo -e "${RED}ERROR: Issue with certificate files ($1 $2) NSI-SNMPMon will fail to start.${NC}"
    echo "You can test this with the following commands:"
    echo "  openssl x509 -in $1 -pubkey -noout -outform pem"
    echo "  openssl pkey -in $2 -pubout -outform pem"
    ERROR=true
  else
    csha=`echo $cdata | sha256sum`
    ksha=`echo $kdata | sha256sum`
    if [ "$csha" = "$ksha" ]; then
      echo "Public keys for cert and key match. OK"
    else
      echo -e "${RED}Public keys for cert and key do not match.${NC}"
      echo "You can test this with the following commands and output must be equal:"
      echo "  openssl x509 -in $1 -pubkey -noout -outform pem | sha256sum"
      echo "  openssl pkey -in $2 -pubout -outform pem | sha256sum"
    fi
    if openssl x509 -checkend 86400 -noout -in $1
    then
      echo -e "Certificate $1 is valid. OK"
    else
      echo -e "${RED}Certificate $1 expired or expires in 1 day. Please update certificate. NSI-SNMPMon will fail to start${NC}"
      ERROR=true
    fi
  fi
  if [ "$ERROR" = true ]; then
    return 1
  fi
  return 0
}

DOCKERNET="-p 8080:80 -p 8443:443"
while getopts i:n: flag
do
  case "${flag}" in
    i) VERSION=${OPTARG};;
    n) NETMODE=${OPTARG}
       if [ "x$NETMODE" != "xhost" ] && [ "x$NETMODE" != "xport" ]; then
         echo "Parameter -n $NETMODE is not one of: host,port."
         exit 1
       elif [ "x$NETMODE" == "xhost" ]; then
         DOCKERNET="--net host"
       else
         DOCKERNET="-p 8080:80 -p 8443:443"
       fi;;
  esac
done

# Do not use json-file logging if it is podman
ISPODMAN=`docker --version | grep podman | wc -l`
LOGOPTIONS=""
if [ $ISPODMAN -eq 0 ]; then
  LOGOPTIONS="--log-driver=json-file --log-opt max-size=10m --log-opt max-file=10"
fi

declare -a ARRAY=("cbe5624a736c0098058ca204fe222d9a89b7db3e  conf/snmp-mon.yaml" "07166fdb7889a194d2c1b5f3ce271c9a244d5e0d  conf/cert.pem" "a4b813fbafbf7ec944fce3d6f0b5bfdff118c06b  conf/privkey.pem")

length=${#ARRAY[@]}

ERROR=false
for (( j=0; j<length; j++ ))
do
  echo "${ARRAY[$j]}" | shasum -c &> /dev/null
  if [ $? == 0 ]; then
    echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
    read -ra strarr <<< "${ARRAY[$j]}"
    echo -e "${RED}ERROR: Configuration file ${strarr[1]} was not modified. NSI-SNMPMon Will fail to start.${NC}"
    echo "Please modify file and set correct values"
    echo "For more details, documentation is available here: https://github.com/sdn-sense/nsi-snmpmon"
    ERROR=true
  fi
done

echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
echo "Testing certificates conf/{cert,privkey}.pem"
certchecker conf/cert.pem conf/privkey.pem
if [ $? != 0 ]; then
  ERROR=true
fi

if [ "$ERROR" = true ]; then
  echo "There was errors in configuration files. NSI-SNMPMon will not start. Please fix errors and try again."
  exit 1
fi


docker run \
       -dit --name nsi-snmpmon \
       -v $(pwd)/conf/snmp-mon.yaml:/etc/snmp-mon.yaml \
       -v $(pwd)/conf/cert.pem:/etc/httpd/certs/cert.pem \
       -v $(pwd)/conf/privkey.pem:/etc/httpd/certs/privkey.pem \
       $DOCKERNET \
       --restart always \
       -e LISTEN_SNMPMON_PORT=8443 \
       $LOGOPTIONS docker.io/sdnsense/nsi-snmpmon:$VERSION

# For development, add -v /home/jbalcas/siterm/:/opt/siterm/sitermcode/siterm/ \
