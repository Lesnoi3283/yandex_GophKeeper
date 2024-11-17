// Code generated by MockGen. DO NOT EDIT.
// Source: required_interfaces.go

// Package mocks is a generated GoMock package.
package mocks

import (
	entities "GophKeeper/internal/app/entities"
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockKeyKeeper is a mock of KeyKeeper interface.
type MockKeyKeeper struct {
	ctrl     *gomock.Controller
	recorder *MockKeyKeeperMockRecorder
}

// MockKeyKeeperMockRecorder is the mock recorder for MockKeyKeeper.
type MockKeyKeeperMockRecorder struct {
	mock *MockKeyKeeper
}

// NewMockKeyKeeper creates a new mock instance.
func NewMockKeyKeeper(ctrl *gomock.Controller) *MockKeyKeeper {
	mock := &MockKeyKeeper{ctrl: ctrl}
	mock.recorder = &MockKeyKeeperMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKeyKeeper) EXPECT() *MockKeyKeeperMockRecorder {
	return m.recorder
}

// GetBankCardKey mocks base method.
func (m *MockKeyKeeper) GetBankCardKey(userID, dataID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBankCardKey", userID, dataID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBankCardKey indicates an expected call of GetBankCardKey.
func (mr *MockKeyKeeperMockRecorder) GetBankCardKey(userID, dataID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBankCardKey", reflect.TypeOf((*MockKeyKeeper)(nil).GetBankCardKey), userID, dataID)
}

// GetBinaryDataKey mocks base method.
func (m *MockKeyKeeper) GetBinaryDataKey(userID, dataID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBinaryDataKey", userID, dataID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBinaryDataKey indicates an expected call of GetBinaryDataKey.
func (mr *MockKeyKeeperMockRecorder) GetBinaryDataKey(userID, dataID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBinaryDataKey", reflect.TypeOf((*MockKeyKeeper)(nil).GetBinaryDataKey), userID, dataID)
}

// GetLoginAndPasswordKey mocks base method.
func (m *MockKeyKeeper) GetLoginAndPasswordKey(userID, dataID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLoginAndPasswordKey", userID, dataID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLoginAndPasswordKey indicates an expected call of GetLoginAndPasswordKey.
func (mr *MockKeyKeeperMockRecorder) GetLoginAndPasswordKey(userID, dataID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLoginAndPasswordKey", reflect.TypeOf((*MockKeyKeeper)(nil).GetLoginAndPasswordKey), userID, dataID)
}

// GetTextDataKey mocks base method.
func (m *MockKeyKeeper) GetTextDataKey(userID, dataID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTextDataKey", userID, dataID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTextDataKey indicates an expected call of GetTextDataKey.
func (mr *MockKeyKeeperMockRecorder) GetTextDataKey(userID, dataID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTextDataKey", reflect.TypeOf((*MockKeyKeeper)(nil).GetTextDataKey), userID, dataID)
}

// SetBankCardKey mocks base method.
func (m *MockKeyKeeper) SetBankCardKey(userID, dataID, key string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetBankCardKey", userID, dataID, key)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetBankCardKey indicates an expected call of SetBankCardKey.
func (mr *MockKeyKeeperMockRecorder) SetBankCardKey(userID, dataID, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetBankCardKey", reflect.TypeOf((*MockKeyKeeper)(nil).SetBankCardKey), userID, dataID, key)
}

// SetBinaryDataKey mocks base method.
func (m *MockKeyKeeper) SetBinaryDataKey(userID, dataID, key string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetBinaryDataKey", userID, dataID, key)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetBinaryDataKey indicates an expected call of SetBinaryDataKey.
func (mr *MockKeyKeeperMockRecorder) SetBinaryDataKey(userID, dataID, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetBinaryDataKey", reflect.TypeOf((*MockKeyKeeper)(nil).SetBinaryDataKey), userID, dataID, key)
}

// SetLoginAndPasswordKey mocks base method.
func (m *MockKeyKeeper) SetLoginAndPasswordKey(userID, dataID, key string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetLoginAndPasswordKey", userID, dataID, key)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetLoginAndPasswordKey indicates an expected call of SetLoginAndPasswordKey.
func (mr *MockKeyKeeperMockRecorder) SetLoginAndPasswordKey(userID, dataID, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetLoginAndPasswordKey", reflect.TypeOf((*MockKeyKeeper)(nil).SetLoginAndPasswordKey), userID, dataID, key)
}

// SetTextDataKey mocks base method.
func (m *MockKeyKeeper) SetTextDataKey(userID, dataID, key string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetTextDataKey", userID, dataID, key)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetTextDataKey indicates an expected call of SetTextDataKey.
func (mr *MockKeyKeeperMockRecorder) SetTextDataKey(userID, dataID, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetTextDataKey", reflect.TypeOf((*MockKeyKeeper)(nil).SetTextDataKey), userID, dataID, key)
}

// MockStorage is a mock of Storage interface.
type MockStorage struct {
	ctrl     *gomock.Controller
	recorder *MockStorageMockRecorder
}

// MockStorageMockRecorder is the mock recorder for MockStorage.
type MockStorageMockRecorder struct {
	mock *MockStorage
}

// NewMockStorage creates a new mock instance.
func NewMockStorage(ctrl *gomock.Controller) *MockStorage {
	mock := &MockStorage{ctrl: ctrl}
	mock.recorder = &MockStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStorage) EXPECT() *MockStorageMockRecorder {
	return m.recorder
}

// GetBankCard mocks base method.
func (m *MockStorage) GetBankCard(ctx context.Context, last4Digits, ownerID int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBankCard", ctx, last4Digits, ownerID)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBankCard indicates an expected call of GetBankCard.
func (mr *MockStorageMockRecorder) GetBankCard(ctx, last4Digits, ownerID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBankCard", reflect.TypeOf((*MockStorage)(nil).GetBankCard), ctx, last4Digits, ownerID)
}

// GetBinaryData mocks base method.
func (m *MockStorage) GetBinaryData(ctx context.Context, ownerID int, dataName string) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBinaryData", ctx, ownerID, dataName)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBinaryData indicates an expected call of GetBinaryData.
func (mr *MockStorageMockRecorder) GetBinaryData(ctx, ownerID, dataName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBinaryData", reflect.TypeOf((*MockStorage)(nil).GetBinaryData), ctx, ownerID, dataName)
}

// GetLoginAndPassword mocks base method.
func (m *MockStorage) GetLoginAndPassword(ctx context.Context, ownerID int, login string) (entities.LoginAndPassword, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLoginAndPassword", ctx, ownerID, login)
	ret0, _ := ret[0].(entities.LoginAndPassword)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLoginAndPassword indicates an expected call of GetLoginAndPassword.
func (mr *MockStorageMockRecorder) GetLoginAndPassword(ctx, ownerID, login interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLoginAndPassword", reflect.TypeOf((*MockStorage)(nil).GetLoginAndPassword), ctx, ownerID, login)
}

// GetText mocks base method.
func (m *MockStorage) GetText(ctx context.Context, ownerID int, textName string) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetText", ctx, ownerID, textName)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetText indicates an expected call of GetText.
func (mr *MockStorageMockRecorder) GetText(ctx, ownerID, textName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetText", reflect.TypeOf((*MockStorage)(nil).GetText), ctx, ownerID, textName)
}

// SaveBankCard mocks base method.
func (m *MockStorage) SaveBankCard(ctx context.Context, userID int, cardData []byte) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveBankCard", ctx, userID, cardData)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SaveBankCard indicates an expected call of SaveBankCard.
func (mr *MockStorageMockRecorder) SaveBankCard(ctx, userID, cardData interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveBankCard", reflect.TypeOf((*MockStorage)(nil).SaveBankCard), ctx, userID, cardData)
}

// SaveBinaryData mocks base method.
func (m *MockStorage) SaveBinaryData(ctx context.Context, ownerID int, dataName string, data []byte) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveBinaryData", ctx, ownerID, dataName, data)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SaveBinaryData indicates an expected call of SaveBinaryData.
func (mr *MockStorageMockRecorder) SaveBinaryData(ctx, ownerID, dataName, data interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveBinaryData", reflect.TypeOf((*MockStorage)(nil).SaveBinaryData), ctx, ownerID, dataName, data)
}

// SaveLoginAndPassword mocks base method.
func (m *MockStorage) SaveLoginAndPassword(ctx context.Context, ownerID int, data entities.LoginAndPassword) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveLoginAndPassword", ctx, ownerID, data)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SaveLoginAndPassword indicates an expected call of SaveLoginAndPassword.
func (mr *MockStorageMockRecorder) SaveLoginAndPassword(ctx, ownerID, data interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveLoginAndPassword", reflect.TypeOf((*MockStorage)(nil).SaveLoginAndPassword), ctx, ownerID, data)
}

// SaveText mocks base method.
func (m *MockStorage) SaveText(ctx context.Context, ownerID int, textName string, text []byte) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveText", ctx, ownerID, textName, text)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SaveText indicates an expected call of SaveText.
func (mr *MockStorageMockRecorder) SaveText(ctx, ownerID, textName, text interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveText", reflect.TypeOf((*MockStorage)(nil).SaveText), ctx, ownerID, textName, text)
}

// MockUserManager is a mock of UserManager interface.
type MockUserManager struct {
	ctrl     *gomock.Controller
	recorder *MockUserManagerMockRecorder
}

// MockUserManagerMockRecorder is the mock recorder for MockUserManager.
type MockUserManagerMockRecorder struct {
	mock *MockUserManager
}

// NewMockUserManager creates a new mock instance.
func NewMockUserManager(ctrl *gomock.Controller) *MockUserManager {
	mock := &MockUserManager{ctrl: ctrl}
	mock.recorder = &MockUserManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserManager) EXPECT() *MockUserManagerMockRecorder {
	return m.recorder
}

// Auth mocks base method.
func (m *MockUserManager) Auth(ctx context.Context, user entities.User) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Auth", ctx, user)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Auth indicates an expected call of Auth.
func (mr *MockUserManagerMockRecorder) Auth(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Auth", reflect.TypeOf((*MockUserManager)(nil).Auth), ctx, user)
}

// Create mocks base method.
func (m *MockUserManager) Create(ctx context.Context, user entities.User) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, user)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockUserManagerMockRecorder) Create(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockUserManager)(nil).Create), ctx, user)
}

// MockJWTHelper is a mock of JWTHelper interface.
type MockJWTHelper struct {
	ctrl     *gomock.Controller
	recorder *MockJWTHelperMockRecorder
}

// MockJWTHelperMockRecorder is the mock recorder for MockJWTHelper.
type MockJWTHelperMockRecorder struct {
	mock *MockJWTHelper
}

// NewMockJWTHelper creates a new mock instance.
func NewMockJWTHelper(ctrl *gomock.Controller) *MockJWTHelper {
	mock := &MockJWTHelper{ctrl: ctrl}
	mock.recorder = &MockJWTHelperMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockJWTHelper) EXPECT() *MockJWTHelperMockRecorder {
	return m.recorder
}

// BuildNewJWTString mocks base method.
func (m *MockJWTHelper) BuildNewJWTString(userID int) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BuildNewJWTString", userID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BuildNewJWTString indicates an expected call of BuildNewJWTString.
func (mr *MockJWTHelperMockRecorder) BuildNewJWTString(userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BuildNewJWTString", reflect.TypeOf((*MockJWTHelper)(nil).BuildNewJWTString), userID)
}

// GetUserID mocks base method.
func (m *MockJWTHelper) GetUserID(token string) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserID", token)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserID indicates an expected call of GetUserID.
func (mr *MockJWTHelperMockRecorder) GetUserID(token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserID", reflect.TypeOf((*MockJWTHelper)(nil).GetUserID), token)
}
