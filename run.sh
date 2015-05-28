#!/bin/bash
./build/CABDaemon 8k_4 9000 stats & pid=$!
{ sleep 2120s; kill $pid; } &
sleep 20s
for i in {5..50..5}
do
    echo running cab ${i}k-0.001-20
    timeout 210s ryu-manager cab_switch_CAB.py <<< "${i}k-0.001-20"
done

./build/CMRDaemon 8k_4 9000 stats & pid=$!
{ sleep 2120s; kill $pid; } &
sleep 20s
for i in {5..50..5}
do
    echo running cmr ${i}k-0.001-20
    timeout 210s ryu-manager cab_switch_CMR.py <<< "${i}k-0.001-20"
done

for i in {5..50..5}
do
    echo running cem ${i}k-0.001-20
    timeout 210s ryu-manager cab_switch_CEM.py <<< "${i}k-0.001-20"
done

timestamp=$(date "+%Y.%m.%d-%H.%M.%S")
echo "Current Time : $timestamp"
