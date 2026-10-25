//go:build !linux

package main

// 非 Linux（开发机 macOS 等）不做指标采集：保持 0，调度退化为纯
// RTT 最短路，与之前行为一致。生产机是 Linux，走 metrics_linux.go。

type cpuSampler struct{}

func (s *cpuSampler) pct() float64 { return 0 }

func memPct() float64 { return 0 }

func diskFree(string) uint64 { return 0 }
