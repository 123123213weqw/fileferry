//go:build unix

package main

import "syscall"

// diskFree 返回 path 所在文件系统的可用字节数。
//
// 之前只在 Linux 实现（读 /proc 那套里），非 Linux 一律返回 0，导致
// 磁盘水位逻辑在 macOS 上完全失效——状态里恒为 0，调度永远认为
// "磁盘充足"。Statfs 在 unix 上都有，用构建标签统一起来。
func diskFree(path string) uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	// Linux: Bsize int64；macOS: Bsize uint32。统一走 uint64 转换。
	return uint64(st.Bavail) * uint64(st.Bsize)
}
