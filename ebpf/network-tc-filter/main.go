// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023 Datadog, Inc.

//go:build !cgo
// +build !cgo

package main

/*
#cgo LDFLAGS: -lelf -lz
#include <bpf/bpf.h>
*/
import "C"

import (
	"flag"
	"unsafe"

	"github.com/DataDog/chaos-controller/log"
	"github.com/aquasecurity/libbpfgo"
	"go.uber.org/zap"
)

var (
	err     error
	logger  *zap.SugaredLogger
	nMethod = flag.String("m", "ALL", "Filter method")
	nPath   = flag.String("f", "/", "Filter path")
)

const ValueSize = 100
const MapName = "flags_map"

func main() {
	flag.Parse()
	path := []byte(*nPath)
	method := []byte(*nMethod)
	logger, err = log.NewZapLogger()
	if err != nil {
		logger.Fatalf("could not initialize the logger: %w", err, err)
	}

	bpfMaps := libbpfgo.GetMapsByName(MapName)

	if len(bpfMaps) == 0 {
		logger.Fatalf("%s not found", MapName)
	}

	bpfMap := bpfMaps[0]

	// Update the PATH
	if err = updateMap(uint32(0), path, ValueSize, bpfMap); err != nil {
		logger.Fatalf("could not update the path: %w", err)
	}

	// Update the METHOD
	if err = updateMap(uint32(1), method, ValueSize, bpfMap); err != nil {
		logger.Fatalf("could not update the method: %w", err)
	}

	logger.Infof("the %s map is updated", MapName)
}

func updateMap(key uint32, value []byte, valueSize int, bpfMap *libbpfgo.BPFMapLow) error {
	valueBytes := make([]byte, valueSize)
	copy(valueBytes[:len(value)], value)

	logger.Debugf("UPDATE MAP %s key: %s, value: %s, value size: %d\n", bpfMap.Name(), key, value, valueSize)

	return bpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&valueBytes[0]))
}
