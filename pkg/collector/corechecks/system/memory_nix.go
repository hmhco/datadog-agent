// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018 Datadog, Inc.

// +build !windows

package system

import (
	"fmt"

	log "github.com/cihub/seelog"
	"github.com/shirou/gopsutil/mem"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
)

// Run executes the check
func (c *MemoryCheck) Run() error {
	sender, err := aggregator.GetSender(c.ID())
	if err != nil {
		return err
	}

	v, errVirt := virtualMemory()
	if errVirt == nil {
		sender.Gauge("system.mem.total", float64(v.Total)/mbSize, "", nil)
		sender.Gauge("system.mem.free", float64(v.Free)/mbSize, "", nil)
		sender.Gauge("system.mem.used", float64(v.Total-v.Free)/mbSize, "", nil)
		sender.Gauge("system.mem.usable", float64(v.Available)/mbSize, "", nil)
		sender.Gauge("system.mem.pct_usable", float64(100-v.UsedPercent)/100, "", nil)

		switch runtimeOS {
		case "linux":
			e := c.linuxSpecificVirtualMemoryCheck(v)
			if e != nil {
				return e
			}
		case "freebsd":
			e := c.freebsdSpecificVirtualMemoryCheck(v)
			if e != nil {
				return e
			}
		}
	} else {
		log.Errorf("system.MemoryCheck: could not retrieve virtual memory stats: %s", errVirt)
	}

	s, errSwap := swapMemory()
	if errSwap == nil {
		sender.Gauge("system.swap.total", float64(s.Total)/mbSize, "", nil)
		sender.Gauge("system.swap.free", float64(s.Free)/mbSize, "", nil)
		sender.Gauge("system.swap.used", float64(s.Used)/mbSize, "", nil)
		sender.Gauge("system.swap.pct_free", float64(100-s.UsedPercent)/100, "", nil)
	} else {
		log.Errorf("system.MemoryCheck: could not retrieve swap memory stats: %s", errSwap)
	}

	if errVirt != nil && errSwap != nil {
		return fmt.Errorf("failed to gather any memory information")
	}

	sender.Commit()
	return nil
}

func (c *MemoryCheck) linuxSpecificVirtualMemoryCheck(v *mem.VirtualMemoryStat) error {
	sender, err := aggregator.GetSender(c.ID())
	if err != nil {
		return err
	}

	sender.Gauge("system.mem.cached", float64(v.Cached)/mbSize, "", nil)
	sender.Gauge("system.mem.shared", float64(v.Shared)/mbSize, "", nil)
	sender.Gauge("system.mem.slab", float64(v.Slab)/mbSize, "", nil)
	sender.Gauge("system.mem.page_tables", float64(v.PageTables)/mbSize, "", nil)
	sender.Gauge("system.swap.cached", float64(v.SwapCached)/mbSize, "", nil)
	return nil
}

func (c *MemoryCheck) freebsdSpecificVirtualMemoryCheck(v *mem.VirtualMemoryStat) error {
	sender, err := aggregator.GetSender(c.ID())
	if err != nil {
		return err
	}

	sender.Gauge("system.mem.cached", float64(v.Cached)/mbSize, "", nil)
	return nil
}