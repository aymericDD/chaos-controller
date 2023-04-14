// Code generated by mockery. DO NOT EDIT.

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023 Datadog, Inc.
package mocks

import mock "github.com/stretchr/testify/mock"

// ResourceEventHandlerMock is an autogenerated mock type for the ResourceEventHandler type
type ResourceEventHandlerMock struct {
	mock.Mock
}

type ResourceEventHandlerMock_Expecter struct {
	mock *mock.Mock
}

func (_m *ResourceEventHandlerMock) EXPECT() *ResourceEventHandlerMock_Expecter {
	return &ResourceEventHandlerMock_Expecter{mock: &_m.Mock}
}

// OnAdd provides a mock function with given fields: obj
func (_m *ResourceEventHandlerMock) OnAdd(obj interface{}) {
	_m.Called(obj)
}

// ResourceEventHandlerMock_OnAdd_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'OnAdd'
type ResourceEventHandlerMock_OnAdd_Call struct {
	*mock.Call
}

// OnAdd is a helper method to define mock.On call
//   - obj interface{}
func (_e *ResourceEventHandlerMock_Expecter) OnAdd(obj interface{}) *ResourceEventHandlerMock_OnAdd_Call {
	return &ResourceEventHandlerMock_OnAdd_Call{Call: _e.mock.On("OnAdd", obj)}
}

func (_c *ResourceEventHandlerMock_OnAdd_Call) Run(run func(obj interface{})) *ResourceEventHandlerMock_OnAdd_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}))
	})
	return _c
}

func (_c *ResourceEventHandlerMock_OnAdd_Call) Return() *ResourceEventHandlerMock_OnAdd_Call {
	_c.Call.Return()
	return _c
}

func (_c *ResourceEventHandlerMock_OnAdd_Call) RunAndReturn(run func(interface{})) *ResourceEventHandlerMock_OnAdd_Call {
	_c.Call.Return(run)
	return _c
}

// OnDelete provides a mock function with given fields: obj
func (_m *ResourceEventHandlerMock) OnDelete(obj interface{}) {
	_m.Called(obj)
}

// ResourceEventHandlerMock_OnDelete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'OnDelete'
type ResourceEventHandlerMock_OnDelete_Call struct {
	*mock.Call
}

// OnDelete is a helper method to define mock.On call
//   - obj interface{}
func (_e *ResourceEventHandlerMock_Expecter) OnDelete(obj interface{}) *ResourceEventHandlerMock_OnDelete_Call {
	return &ResourceEventHandlerMock_OnDelete_Call{Call: _e.mock.On("OnDelete", obj)}
}

func (_c *ResourceEventHandlerMock_OnDelete_Call) Run(run func(obj interface{})) *ResourceEventHandlerMock_OnDelete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}))
	})
	return _c
}

func (_c *ResourceEventHandlerMock_OnDelete_Call) Return() *ResourceEventHandlerMock_OnDelete_Call {
	_c.Call.Return()
	return _c
}

func (_c *ResourceEventHandlerMock_OnDelete_Call) RunAndReturn(run func(interface{})) *ResourceEventHandlerMock_OnDelete_Call {
	_c.Call.Return(run)
	return _c
}

// OnUpdate provides a mock function with given fields: oldObj, newObj
func (_m *ResourceEventHandlerMock) OnUpdate(oldObj interface{}, newObj interface{}) {
	_m.Called(oldObj, newObj)
}

// ResourceEventHandlerMock_OnUpdate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'OnUpdate'
type ResourceEventHandlerMock_OnUpdate_Call struct {
	*mock.Call
}

// OnUpdate is a helper method to define mock.On call
//   - oldObj interface{}
//   - newObj interface{}
func (_e *ResourceEventHandlerMock_Expecter) OnUpdate(oldObj interface{}, newObj interface{}) *ResourceEventHandlerMock_OnUpdate_Call {
	return &ResourceEventHandlerMock_OnUpdate_Call{Call: _e.mock.On("OnUpdate", oldObj, newObj)}
}

func (_c *ResourceEventHandlerMock_OnUpdate_Call) Run(run func(oldObj interface{}, newObj interface{})) *ResourceEventHandlerMock_OnUpdate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}), args[1].(interface{}))
	})
	return _c
}

func (_c *ResourceEventHandlerMock_OnUpdate_Call) Return() *ResourceEventHandlerMock_OnUpdate_Call {
	_c.Call.Return()
	return _c
}

func (_c *ResourceEventHandlerMock_OnUpdate_Call) RunAndReturn(run func(interface{}, interface{})) *ResourceEventHandlerMock_OnUpdate_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewResourceEventHandlerMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewResourceEventHandlerMock creates a new instance of ResourceEventHandlerMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewResourceEventHandlerMock(t mockConstructorTestingTNewResourceEventHandlerMock) *ResourceEventHandlerMock {
	mock := &ResourceEventHandlerMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
