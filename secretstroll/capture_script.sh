#!/bin/bash

for i in {1..100}
do
    for j in {1..100}
    do
        python3 client.py grid $i -T restaurant -t &
        grid_pid=$! 
        tcpdump host tor.nordu.net -w network_traces/pcap_network_traces_$i\_$j.pcap &
        wait $grid_pid
        kill -2 $!
    done
done