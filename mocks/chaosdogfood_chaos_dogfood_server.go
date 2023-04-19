// Code generated by mockery. DO NOT EDIT.

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023 Datadog, Inc.
package mocks

import (
	context "context"

	chaosdogfood "github.com/DataDog/chaos-controller/dogfood/chaosdogfood"

	emptypb "google.golang.org/protobuf/types/known/emptypb"

	mock "github.com/stretchr/testify/mock"
)

// ChaosDogfoodServerMock is an autogenerated mock type for the ChaosDogfoodServer type
type ChaosDogfoodServerMock struct {
	mock.Mock
}

type ChaosDogfoodServerMock_Expecter struct {
	mock *mock.Mock
}

func (_m *ChaosDogfoodServerMock) EXPECT() *ChaosDogfoodServerMock_Expecter {
	return &ChaosDogfoodServerMock_Expecter{mock: &_m.Mock}
}

// GetCatalog provides a mock function with given fields: _a0, _a1
func (_m *ChaosDogfoodServerMock) GetCatalog(_a0 context.Context, _a1 *emptypb.Empty) (*chaosdogfood.CatalogReply, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *chaosdogfood.CatalogReply
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *emptypb.Empty) (*chaosdogfood.CatalogReply, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *emptypb.Empty) *chaosdogfood.CatalogReply); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*chaosdogfood.CatalogReply)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *emptypb.Empty) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ChaosDogfoodServerMock_GetCatalog_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCatalog'
type ChaosDogfoodServerMock_GetCatalog_Call struct {
	*mock.Call
}

// GetCatalog is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *emptypb.Empty
func (_e *ChaosDogfoodServerMock_Expecter) GetCatalog(_a0 interface{}, _a1 interface{}) *ChaosDogfoodServerMock_GetCatalog_Call {
	return &ChaosDogfoodServerMock_GetCatalog_Call{Call: _e.mock.On("GetCatalog", _a0, _a1)}
}

func (_c *ChaosDogfoodServerMock_GetCatalog_Call) Run(run func(_a0 context.Context, _a1 *emptypb.Empty)) *ChaosDogfoodServerMock_GetCatalog_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*emptypb.Empty))
	})
	return _c
}

func (_c *ChaosDogfoodServerMock_GetCatalog_Call) Return(_a0 *chaosdogfood.CatalogReply, _a1 error) *ChaosDogfoodServerMock_GetCatalog_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ChaosDogfoodServerMock_GetCatalog_Call) RunAndReturn(run func(context.Context, *emptypb.Empty) (*chaosdogfood.CatalogReply, error)) *ChaosDogfoodServerMock_GetCatalog_Call {
	_c.Call.Return(run)
	return _c
}

// Order provides a mock function with given fields: _a0, _a1
func (_m *ChaosDogfoodServerMock) Order(_a0 context.Context, _a1 *chaosdogfood.FoodRequest) (*chaosdogfood.FoodReply, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *chaosdogfood.FoodReply
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *chaosdogfood.FoodRequest) (*chaosdogfood.FoodReply, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *chaosdogfood.FoodRequest) *chaosdogfood.FoodReply); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*chaosdogfood.FoodReply)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *chaosdogfood.FoodRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ChaosDogfoodServerMock_Order_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Order'
type ChaosDogfoodServerMock_Order_Call struct {
	*mock.Call
}

// Order is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *chaosdogfood.FoodRequest
func (_e *ChaosDogfoodServerMock_Expecter) Order(_a0 interface{}, _a1 interface{}) *ChaosDogfoodServerMock_Order_Call {
	return &ChaosDogfoodServerMock_Order_Call{Call: _e.mock.On("Order", _a0, _a1)}
}

func (_c *ChaosDogfoodServerMock_Order_Call) Run(run func(_a0 context.Context, _a1 *chaosdogfood.FoodRequest)) *ChaosDogfoodServerMock_Order_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*chaosdogfood.FoodRequest))
	})
	return _c
}

func (_c *ChaosDogfoodServerMock_Order_Call) Return(_a0 *chaosdogfood.FoodReply, _a1 error) *ChaosDogfoodServerMock_Order_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ChaosDogfoodServerMock_Order_Call) RunAndReturn(run func(context.Context, *chaosdogfood.FoodRequest) (*chaosdogfood.FoodReply, error)) *ChaosDogfoodServerMock_Order_Call {
	_c.Call.Return(run)
	return _c
}

// mustEmbedUnimplementedChaosDogfoodServer provides a mock function with given fields:
func (_m *ChaosDogfoodServerMock) mustEmbedUnimplementedChaosDogfoodServer() {
	_m.Called()
}

// ChaosDogfoodServerMock_mustEmbedUnimplementedChaosDogfoodServer_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'mustEmbedUnimplementedChaosDogfoodServer'
type ChaosDogfoodServerMock_mustEmbedUnimplementedChaosDogfoodServer_Call struct {
	*mock.Call
}

// mustEmbedUnimplementedChaosDogfoodServer is a helper method to define mock.On call
func (_e *ChaosDogfoodServerMock_Expecter) mustEmbedUnimplementedChaosDogfoodServer() *ChaosDogfoodServerMock_mustEmbedUnimplementedChaosDogfoodServer_Call {
	return &ChaosDogfoodServerMock_mustEmbedUnimplementedChaosDogfoodServer_Call{Call: _e.mock.On("mustEmbedUnimplementedChaosDogfoodServer")}
}

func (_c *ChaosDogfoodServerMock_mustEmbedUnimplementedChaosDogfoodServer_Call) Run(run func()) *ChaosDogfoodServerMock_mustEmbedUnimplementedChaosDogfoodServer_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ChaosDogfoodServerMock_mustEmbedUnimplementedChaosDogfoodServer_Call) Return() *ChaosDogfoodServerMock_mustEmbedUnimplementedChaosDogfoodServer_Call {
	_c.Call.Return()
	return _c
}

func (_c *ChaosDogfoodServerMock_mustEmbedUnimplementedChaosDogfoodServer_Call) RunAndReturn(run func()) *ChaosDogfoodServerMock_mustEmbedUnimplementedChaosDogfoodServer_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewChaosDogfoodServerMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewChaosDogfoodServerMock creates a new instance of ChaosDogfoodServerMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewChaosDogfoodServerMock(t mockConstructorTestingTNewChaosDogfoodServerMock) *ChaosDogfoodServerMock {
	mock := &ChaosDogfoodServerMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}