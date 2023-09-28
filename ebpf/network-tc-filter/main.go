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
	"fmt"
	"github.com/DataDog/chaos-controller/log"
	"go.uber.org/zap"
	"syscall"
	"unsafe"
)

var (
	err     error
	logger  *zap.SugaredLogger
	nMethod = flag.String("m", "ALL", "Filter method")
	nPath   = flag.String("f", "/", "Filter path")
)

const ValueSize = 100
const FlagsMapName = "flags_map"
const MAX_PATH_LEN = 20
const MAX_ENTRIES = 5
const MAX_METHOD_LEN = 10

type BPFMap struct {
	name string
	fd   C.int
}

// Define a Go struct that matches the layout of the value in the BPF map
type MethodPaths struct {
	Paths [MAX_ENTRIES][MAX_PATH_LEN]byte
}

func (b *BPFMap) Update(key, value unsafe.Pointer) error {
	errC := C.bpf_map_update_elem(b.fd, key, value, C.ulonglong(0))
	if errC != 0 {
		return fmt.Errorf("failed to update map %s: %w", b.name, syscall.Errno(-errC))
	}
	return nil
}

func main() {
	flag.Parse()
	//path := []byte(*nPath)
	//method := []byte(*nMethod)
	logger, err = log.NewZapLogger()
	if err != nil {
		logger.Fatalf("could not initialize the logger: %w", err, err)
	}

	//bpfMap, err := GetMapByName("flags_map")
	//if err != nil {
	//	logger.Fatalf("could not get the flags_map: %w", err)
	//}
	//
	//// Update the path
	//if err = updateMap(uint32(0), path, ValueSize, bpfMap); err != nil {
	//	logger.Fatalf("could not update the path: %w", err)
	//}
	//
	//// Update the method
	//if err = updateMap(uint32(1), method, ValueSize, bpfMap); err != nil {
	//	logger.Fatalf("could not update the method: %w", err)
	//}

	//logger.Infof("the %s map is updated", FlagsMapName)

	configBPFMap, err := GetMapByName("config_map")
	if err != nil {
		logger.Fatalf("could not get the config_map: %w", err)
	}

	methodGET := [MAX_METHOD_LEN]byte{'G', 'E', 'T', '\x00'}

	// Create an instance of the MethodPaths struct
	var value MethodPaths
	// Add paths to the MethodPaths struct (example)
	path1 := "/path1"
	path2 := "/"
	copy(value.Paths[0][:len(path1)], path1)
	copy(value.Paths[1][:len(path2)], path2)

	// Serialize the MethodPaths struct into a byte slice
	valueBytes := (*[unsafe.Sizeof(value)]byte)(unsafe.Pointer(&value))[:]

	configBPFMap.Update(unsafe.Pointer(&methodGET), unsafe.Pointer(&valueBytes[0]))

	//methodDELETE := C.CString("DELETE")

	//// Create an instance of the MethodPaths struct
	//var value2 MethodPaths
	//// Add paths to the MethodPaths struct (example)
	//copy(value2.Paths[0][:MAX_PATH_LEN], path1)
	//copy(value2.Paths[1][:MAX_PATH_LEN], path2)
	//value2.NumPaths = int32(2)
	//
	//// Serialize the MethodPaths struct into a byte slice
	//value2Bytes := (*[unsafe.Sizeof(value2)]byte)(unsafe.Pointer(&value2))[:]
	//
	//configBPFMap.Update(unsafe.Pointer(&methodDELETE), unsafe.Pointer(&value2Bytes[0]))
}

func updateMap(key uint32, value []byte, valueSize int, bpfMap *BPFMap) error {
	valueBytes := make([]byte, valueSize)
	copy(valueBytes[:len(value)], value)

	logger.Debugf("UPDATE MAP %s key: %s, value: %s, value size: %d\n", bpfMap.name, key, value, valueSize)

	return bpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&valueBytes[0]))
}

func GetMapByName(name string) (*BPFMap, error) {
	id := C.uint(0)

	for {
		err := C.bpf_map_get_next_id(id, &id)
		if err != 0 {
			return nil, fmt.Errorf("could not get the map: %w", syscall.Errno(-err))
		}

		fd := C.bpf_map_get_fd_by_id(id)
		if fd < 0 {
			return nil, fmt.Errorf("could not get the file descriptor of %s", name)
		}

		info := C.struct_bpf_map_info{}
		infolen := C.uint(unsafe.Sizeof(info))
		err = C.bpf_obj_get_info_by_fd(fd, unsafe.Pointer(&info), &infolen)
		if err != 0 {
			return nil, fmt.Errorf("could not get the map info: %w", syscall.Errno(-err))
		}

		mapName := C.GoString((*C.char)(unsafe.Pointer(&info.name[0])))
		logger.Infof("id: %d name: %s", id, mapName)
		if mapName != name {
			continue
		}

		return &BPFMap{
			name: name,
			fd:   fd,
		}, nil
	}
	return nil, fmt.Errorf("the %s map does not exists", name)
}
