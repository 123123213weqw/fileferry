//go:build !linux

package main

// 非 Linux（BSD 等）不做 CPU/内存采集：保持 0，调度退化为纯
// RTT 最短路。磁盘余量由 metrics_disk_unix.go 提供，跨平台可用。

type cpuSampler struct{}

func (s *cpuSampler) pct() float64 { return 0 }

func memPct() float64 { return 0 }
