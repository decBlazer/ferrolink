# FerroLink Latency Benchmark – Sample Results

This file contains one **non-scientific** run of the `bench/latency.sh` script executed on a Gigabit-LAN between a Linux desktop (agent) and a laptop (client).

```bash
$ ./bench/latency.sh 192.168.1.42 8080 100
p50=78 ms  p90=94 ms  max=112 ms  samples=100
```

All percentiles are comfortably below the 150 ms design goal. Repeat under your own conditions for fresh numbers. 