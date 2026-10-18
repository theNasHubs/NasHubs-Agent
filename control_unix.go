//go:build linux

package main

import "syscall"

func setControlUmask() int        { return syscall.Umask(0077) }
func restoreControlUmask(old int) { syscall.Umask(old) }
