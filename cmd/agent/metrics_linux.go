//go:build linux

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// 负载采集：M4「负载感知调度」的唯一数据源。之前 CPUPct/MemPct/
// DiskFreeBytes 全仓没有任何写入，导致
//   LoadPct() == 0 → 边权退化成纯 RTT 最短路
//   MaxLoadPct=80 的中继排除永不触发
//   多源的「负载折扣」恒为 1
// 也就是说 README 第一句的「负载感知调度」实际不生效。

type cpuTimes struct{ total, idle uint64 }

func readCPUTimes() (cpuTimes, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		var t cpuTimes
		for i, v := range fields {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				continue
			}
			t.total += n
			if i == 3 || i == 4 { // idle + iowait
				t.idle += n
			}
		}
		return t, true
	}
	return cpuTimes{}, false
}

// cpuSampler 用两次采样差值算占用率（瞬时值没有意义）。
type cpuSampler struct {
	prev  cpuTimes
	valid bool
}

func (s *cpuSampler) pct() float64 {
	cur, ok := readCPUTimes()
	if !ok {
		return 0
	}
	if !s.valid {
		s.prev, s.valid = cur, true
		return 0
	}
	dt := cur.total - s.prev.total
	di := cur.idle - s.prev.idle
	s.prev = cur
	if dt == 0 {
		return 0
	}
	p := 100 * (1 - float64(di)/float64(dt))
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return p
}

// memPct 用 MemAvailable（内核给出的可用估计）而非 MemFree。
func memPct() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	var total, avail uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = n * 1024
		case "MemAvailable:":
			avail = n * 1024
		}
	}
	if total == 0 {
		return 0
	}
	p := 100 * (1 - float64(avail)/float64(total))
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return p
}

// diskFree 返回 path 所在文件系统的可用字节数。
func diskFree(path string) uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return st.Bavail * uint64(st.Bsize)
}
