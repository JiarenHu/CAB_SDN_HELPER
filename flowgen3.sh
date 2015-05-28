#!/bin/bash
sleep 20s
for i in {5..50..5}
do
    sleep 10s
    timeout 200s sudo ./build/FlowGen3 ../CAB_SDN/build/Trace_Generate/trace-${i}k-0.001-20/GENtrace/ref_trace.gz -i eth2 1
done

sleep 20s
for i in {5..50..5}
do
    sleep 10s
    timeout 200s sudo ./build/FlowGen3 ../CAB_SDN/build/Trace_Generate/trace-${i}k-0.001-20/GENtrace/ref_trace.gz -i eth2 1
done

for i in {5..50..5}
do
    sleep 10s
    timeout 200s sudo ./build/FlowGen3 ../CAB_SDN/build/Trace_Generate/trace-${i}k-0.001-20/GENtrace/ref_trace.gz -i eth2 1
done

timestamp=$(date "+%Y.%m.%d-%H.%M.%S")
echo "Current Time : $timestamp"

