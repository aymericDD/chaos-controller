// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023 Datadog, Inc.

package injector_test

import (
	v1beta1 "github.com/DataDog/chaos-controller/api/v1beta1"
	"github.com/DataDog/chaos-controller/container"
	. "github.com/DataDog/chaos-controller/injector"
	"github.com/DataDog/chaos-controller/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"os"
	"time"
)

var _ = Describe("Failure", func() {
	var (
		config        DiskFailureInjectorConfig
		level         types.DisruptionLevel
		proc          *os.Process
		inj           Injector
		spec          v1beta1.DiskFailureSpec
		commandMock   BPFDiskFailureCommandMock
		containerMock *container.ContainerMock
	)

	JustBeforeEach(func() {
		const PID = 1
		proc = &os.Process{Pid: PID}

		containerMock = &container.ContainerMock{}
		containerMock.On("PID").Return(uint32(PID))

		commandMock = BPFDiskFailureCommandMock{}
		commandMock.On("Run", mock.Anything, mock.Anything).Return(nil)

		config = DiskFailureInjectorConfig{
			Config: Config{
				Log:             log,
				MetricsSink:     ms,
				Level:           level,
				TargetContainer: containerMock,
			},
			Cmd: &commandMock,
		}

		spec = v1beta1.DiskFailureSpec{
			Path: "/",
		}

		var err error
		inj, err = NewDiskFailureInjector(spec, config)

		Expect(err).To(BeNil())
	})

	Describe("injection", func() {
		JustBeforeEach(func() {
			Eventually(func() bool {
				return Expect(inj.Inject()).To(BeNil())
			}, time.Second*1, time.Second).Should(BeTrue())
		})

		Context("with a pod level", func() {
			BeforeEach(func() {
				level = types.DisruptionLevelPod
			})

			It("should start the eBPF Disk failure program", func() {
				commandMock.AssertCalled(GinkgoT(), "Run", proc.Pid, "/")
			})
		})

		Context("with a node level", func() {
			BeforeEach(func() {
				level = types.DisruptionLevelNode
			})

			It("should start the eBPF Disk failure program", func() {
				commandMock.AssertCalled(GinkgoT(), "Run", 0, "/")
			})
		})
	})
})