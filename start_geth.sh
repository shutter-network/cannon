#! /usr/bin/env bash

set -eu

mkdir -p ${SHROOT}
DATADIR=${SHROOT}/geth-chain
PKFILE=${SHROOT}/privkey.txt

PK=b0057716d5917badaf911b193b12b910811c1497b5bada8d7711f758981c3773
ADDR=0x1dF62f291b2E969fB0849d99D9Ce41e2F137006e

rm -rf ${DATADIR}
echo ${PK} >${PKFILE}
yes "" | geth --datadir ${DATADIR} account import ${PKFILE}
rm ${PKFILE}
exec geth --dev --dev.period=3 --datadir ${DATADIR} --miner.etherbase=${ADDR} --http --http.port 8545 --http.api personal,eth,net,web3,debug --http.corsdomain "*" --ws --ws.port 8546 --ws.api personal,eth,net,web3,debug --gcmode archive --rpc.allow-unprotected-txs
