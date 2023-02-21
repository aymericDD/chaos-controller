// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023 Datadog, Inc.

package ddmark_test

import (
	"fmt"
	"testing"

	"github.com/DataDog/chaos-controller/ddmark"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestValidationTest(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ValidationTest Suite")
}

var _ddmark ddmark.DDMark

var _ = BeforeSuite(func() {
	var err error
	_ddmark, err = ddmark.NewDDMark(ddmark.MarkedLib{ddmark.EmbeddedDDMarkAPI, "ddmark-api"})
	if err != nil {
		fmt.Println("error setting up ddmark")
	}
})

var _ = AfterSuite(func() {
	_ddmark.CleanupLibraries()
})
