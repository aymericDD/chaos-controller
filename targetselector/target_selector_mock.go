// Code generated by mockery. DO NOT EDIT.

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023 Datadog, Inc.
package targetselector

import (
	mock "github.com/stretchr/testify/mock"
	client "sigs.k8s.io/controller-runtime/pkg/client"

	v1 "k8s.io/api/core/v1"

	v1beta1 "github.com/DataDog/chaos-controller/api/v1beta1"
)

// TargetSelectorMock is an autogenerated mock type for the TargetSelector type
type TargetSelectorMock struct {
	mock.Mock
}

type TargetSelectorMock_Expecter struct {
	mock *mock.Mock
}

func (_m *TargetSelectorMock) EXPECT() *TargetSelectorMock_Expecter {
	return &TargetSelectorMock_Expecter{mock: &_m.Mock}
}

// GetMatchingNodesOverTotalNodes provides a mock function with given fields: c, instance
func (_m *TargetSelectorMock) GetMatchingNodesOverTotalNodes(c client.Client, instance *v1beta1.Disruption) (*v1.NodeList, int, error) {
	ret := _m.Called(c, instance)

	var r0 *v1.NodeList
	var r1 int
	var r2 error
	if rf, ok := ret.Get(0).(func(client.Client, *v1beta1.Disruption) (*v1.NodeList, int, error)); ok {
		return rf(c, instance)
	}
	if rf, ok := ret.Get(0).(func(client.Client, *v1beta1.Disruption) *v1.NodeList); ok {
		r0 = rf(c, instance)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*v1.NodeList)
		}
	}

	if rf, ok := ret.Get(1).(func(client.Client, *v1beta1.Disruption) int); ok {
		r1 = rf(c, instance)
	} else {
		r1 = ret.Get(1).(int)
	}

	if rf, ok := ret.Get(2).(func(client.Client, *v1beta1.Disruption) error); ok {
		r2 = rf(c, instance)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// TargetSelectorMock_GetMatchingNodesOverTotalNodes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetMatchingNodesOverTotalNodes'
type TargetSelectorMock_GetMatchingNodesOverTotalNodes_Call struct {
	*mock.Call
}

// GetMatchingNodesOverTotalNodes is a helper method to define mock.On call
//   - c client.Client
//   - instance *v1beta1.Disruption
func (_e *TargetSelectorMock_Expecter) GetMatchingNodesOverTotalNodes(c interface{}, instance interface{}) *TargetSelectorMock_GetMatchingNodesOverTotalNodes_Call {
	return &TargetSelectorMock_GetMatchingNodesOverTotalNodes_Call{Call: _e.mock.On("GetMatchingNodesOverTotalNodes", c, instance)}
}

func (_c *TargetSelectorMock_GetMatchingNodesOverTotalNodes_Call) Run(run func(c client.Client, instance *v1beta1.Disruption)) *TargetSelectorMock_GetMatchingNodesOverTotalNodes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.Client), args[1].(*v1beta1.Disruption))
	})
	return _c
}

func (_c *TargetSelectorMock_GetMatchingNodesOverTotalNodes_Call) Return(_a0 *v1.NodeList, _a1 int, _a2 error) *TargetSelectorMock_GetMatchingNodesOverTotalNodes_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *TargetSelectorMock_GetMatchingNodesOverTotalNodes_Call) RunAndReturn(run func(client.Client, *v1beta1.Disruption) (*v1.NodeList, int, error)) *TargetSelectorMock_GetMatchingNodesOverTotalNodes_Call {
	_c.Call.Return(run)
	return _c
}

// GetMatchingPodsOverTotalPods provides a mock function with given fields: c, instance
func (_m *TargetSelectorMock) GetMatchingPodsOverTotalPods(c client.Client, instance *v1beta1.Disruption) (*v1.PodList, int, error) {
	ret := _m.Called(c, instance)

	var r0 *v1.PodList
	var r1 int
	var r2 error
	if rf, ok := ret.Get(0).(func(client.Client, *v1beta1.Disruption) (*v1.PodList, int, error)); ok {
		return rf(c, instance)
	}
	if rf, ok := ret.Get(0).(func(client.Client, *v1beta1.Disruption) *v1.PodList); ok {
		r0 = rf(c, instance)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*v1.PodList)
		}
	}

	if rf, ok := ret.Get(1).(func(client.Client, *v1beta1.Disruption) int); ok {
		r1 = rf(c, instance)
	} else {
		r1 = ret.Get(1).(int)
	}

	if rf, ok := ret.Get(2).(func(client.Client, *v1beta1.Disruption) error); ok {
		r2 = rf(c, instance)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// TargetSelectorMock_GetMatchingPodsOverTotalPods_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetMatchingPodsOverTotalPods'
type TargetSelectorMock_GetMatchingPodsOverTotalPods_Call struct {
	*mock.Call
}

// GetMatchingPodsOverTotalPods is a helper method to define mock.On call
//   - c client.Client
//   - instance *v1beta1.Disruption
func (_e *TargetSelectorMock_Expecter) GetMatchingPodsOverTotalPods(c interface{}, instance interface{}) *TargetSelectorMock_GetMatchingPodsOverTotalPods_Call {
	return &TargetSelectorMock_GetMatchingPodsOverTotalPods_Call{Call: _e.mock.On("GetMatchingPodsOverTotalPods", c, instance)}
}

func (_c *TargetSelectorMock_GetMatchingPodsOverTotalPods_Call) Run(run func(c client.Client, instance *v1beta1.Disruption)) *TargetSelectorMock_GetMatchingPodsOverTotalPods_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.Client), args[1].(*v1beta1.Disruption))
	})
	return _c
}

func (_c *TargetSelectorMock_GetMatchingPodsOverTotalPods_Call) Return(_a0 *v1.PodList, _a1 int, _a2 error) *TargetSelectorMock_GetMatchingPodsOverTotalPods_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *TargetSelectorMock_GetMatchingPodsOverTotalPods_Call) RunAndReturn(run func(client.Client, *v1beta1.Disruption) (*v1.PodList, int, error)) *TargetSelectorMock_GetMatchingPodsOverTotalPods_Call {
	_c.Call.Return(run)
	return _c
}

// TargetIsHealthy provides a mock function with given fields: target, c, instance
func (_m *TargetSelectorMock) TargetIsHealthy(target string, c client.Client, instance *v1beta1.Disruption) error {
	ret := _m.Called(target, c, instance)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, client.Client, *v1beta1.Disruption) error); ok {
		r0 = rf(target, c, instance)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TargetSelectorMock_TargetIsHealthy_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'TargetIsHealthy'
type TargetSelectorMock_TargetIsHealthy_Call struct {
	*mock.Call
}

// TargetIsHealthy is a helper method to define mock.On call
//   - target string
//   - c client.Client
//   - instance *v1beta1.Disruption
func (_e *TargetSelectorMock_Expecter) TargetIsHealthy(target interface{}, c interface{}, instance interface{}) *TargetSelectorMock_TargetIsHealthy_Call {
	return &TargetSelectorMock_TargetIsHealthy_Call{Call: _e.mock.On("TargetIsHealthy", target, c, instance)}
}

func (_c *TargetSelectorMock_TargetIsHealthy_Call) Run(run func(target string, c client.Client, instance *v1beta1.Disruption)) *TargetSelectorMock_TargetIsHealthy_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(client.Client), args[2].(*v1beta1.Disruption))
	})
	return _c
}

func (_c *TargetSelectorMock_TargetIsHealthy_Call) Return(_a0 error) *TargetSelectorMock_TargetIsHealthy_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *TargetSelectorMock_TargetIsHealthy_Call) RunAndReturn(run func(string, client.Client, *v1beta1.Disruption) error) *TargetSelectorMock_TargetIsHealthy_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewTargetSelectorMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewTargetSelectorMock creates a new instance of TargetSelectorMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewTargetSelectorMock(t mockConstructorTestingTNewTargetSelectorMock) *TargetSelectorMock {
	mock := &TargetSelectorMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
