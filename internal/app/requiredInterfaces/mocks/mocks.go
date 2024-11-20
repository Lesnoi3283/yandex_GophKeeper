// Code generated by MockGen. DO NOT EDIT.
// Source: required_interfaces.go

// Package mocks is a generated GoMock package.
package mocks

import (
	entities "GophKeeper/internal/app/entities"
	context "context"
	io "io"
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
func (m *MockKeyKeeper) GetBinaryDataKey(userID, dataName string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBinaryDataKey", userID, dataName)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBinaryDataKey indicates an expected call of GetBinaryDataKey.
func (mr *MockKeyKeeperMockRecorder) GetBinaryDataKey(userID, dataName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBinaryDataKey", reflect.TypeOf((*MockKeyKeeper)(nil).GetBinaryDataKey), userID, dataName)
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
func (m *MockKeyKeeper) SetBinaryDataKey(userID, dataName, key string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetBinaryDataKey", userID, dataName, key)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetBinaryDataKey indicates an expected call of SetBinaryDataKey.
func (mr *MockKeyKeeperMockRecorder) SetBinaryDataKey(userID, dataName, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetBinaryDataKey", reflect.TypeOf((*MockKeyKeeper)(nil).SetBinaryDataKey), userID, dataName, key)
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
func (m *MockStorage) GetBankCard(ctx context.Context, ownerID, last4Digits int) ([]byte, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBankCard", ctx, ownerID, last4Digits)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(int)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetBankCard indicates an expected call of GetBankCard.
func (mr *MockStorageMockRecorder) GetBankCard(ctx, ownerID, last4Digits interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBankCard", reflect.TypeOf((*MockStorage)(nil).GetBankCard), ctx, ownerID, last4Digits)
}

// GetBinaryData mocks base method.
func (m *MockStorage) GetBinaryData(ctx context.Context, ownerID int, dataName string) ([]byte, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBinaryData", ctx, ownerID, dataName)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(int)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetBinaryData indicates an expected call of GetBinaryData.
func (mr *MockStorageMockRecorder) GetBinaryData(ctx, ownerID, dataName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBinaryData", reflect.TypeOf((*MockStorage)(nil).GetBinaryData), ctx, ownerID, dataName)
}

// GetPasswordByLogin mocks base method.
func (m *MockStorage) GetPasswordByLogin(ctx context.Context, ownerID int, login string) (string, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPasswordByLogin", ctx, ownerID, login)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(int)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetPasswordByLogin indicates an expected call of GetPasswordByLogin.
func (mr *MockStorageMockRecorder) GetPasswordByLogin(ctx, ownerID, login interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPasswordByLogin", reflect.TypeOf((*MockStorage)(nil).GetPasswordByLogin), ctx, ownerID, login)
}

// GetText mocks base method.
func (m *MockStorage) GetText(ctx context.Context, ownerID int, textName string) ([]byte, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetText", ctx, ownerID, textName)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(int)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetText indicates an expected call of GetText.
func (mr *MockStorageMockRecorder) GetText(ctx, ownerID, textName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetText", reflect.TypeOf((*MockStorage)(nil).GetText), ctx, ownerID, textName)
}

// SaveBankCard mocks base method.
func (m *MockStorage) SaveBankCard(ctx context.Context, ownerID, lastFourDigits int, cardData []byte) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveBankCard", ctx, ownerID, lastFourDigits, cardData)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SaveBankCard indicates an expected call of SaveBankCard.
func (mr *MockStorageMockRecorder) SaveBankCard(ctx, ownerID, lastFourDigits, cardData interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveBankCard", reflect.TypeOf((*MockStorage)(nil).SaveBankCard), ctx, ownerID, lastFourDigits, cardData)
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
func (m *MockStorage) SaveLoginAndPassword(ctx context.Context, ownerID int, login, password string) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveLoginAndPassword", ctx, ownerID, login, password)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SaveLoginAndPassword indicates an expected call of SaveLoginAndPassword.
func (mr *MockStorageMockRecorder) SaveLoginAndPassword(ctx, ownerID, login, password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveLoginAndPassword", reflect.TypeOf((*MockStorage)(nil).SaveLoginAndPassword), ctx, ownerID, login, password)
}

// SaveText mocks base method.
func (m *MockStorage) SaveText(ctx context.Context, ownerID int, textName, text string) (int, error) {
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

// AuthUser mocks base method.
func (m *MockUserManager) AuthUser(ctx context.Context, user entities.User) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthUser", ctx, user)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthUser indicates an expected call of AuthUser.
func (mr *MockUserManagerMockRecorder) AuthUser(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthUser", reflect.TypeOf((*MockUserManager)(nil).AuthUser), ctx, user)
}

// CreateUser mocks base method.
func (m *MockUserManager) CreateUser(ctx context.Context, user entities.User) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUser", ctx, user)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser.
func (mr *MockUserManagerMockRecorder) CreateUser(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*MockUserManager)(nil).CreateUser), ctx, user)
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

// MockEncryptor is a mock of Encryptor interface.
type MockEncryptor struct {
	ctrl     *gomock.Controller
	recorder *MockEncryptorMockRecorder
}

// MockEncryptorMockRecorder is the mock recorder for MockEncryptor.
type MockEncryptorMockRecorder struct {
	mock *MockEncryptor
}

// NewMockEncryptor creates a new mock instance.
func NewMockEncryptor(ctrl *gomock.Controller) *MockEncryptor {
	mock := &MockEncryptor{ctrl: ctrl}
	mock.recorder = &MockEncryptorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEncryptor) EXPECT() *MockEncryptorMockRecorder {
	return m.recorder
}

// DecryptAESGCM mocks base method.
func (m *MockEncryptor) DecryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DecryptAESGCM", ciphertext, key)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DecryptAESGCM indicates an expected call of DecryptAESGCM.
func (mr *MockEncryptorMockRecorder) DecryptAESGCM(ciphertext, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptAESGCM", reflect.TypeOf((*MockEncryptor)(nil).DecryptAESGCM), ciphertext, key)
}

// EncryptAESGCM mocks base method.
func (m *MockEncryptor) EncryptAESGCM(plaintext, key []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EncryptAESGCM", plaintext, key)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EncryptAESGCM indicates an expected call of EncryptAESGCM.
func (mr *MockEncryptorMockRecorder) EncryptAESGCM(plaintext, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptAESGCM", reflect.TypeOf((*MockEncryptor)(nil).EncryptAESGCM), plaintext, key)
}

// MockEncryptionWriterReaderFabric is a mock of EncryptionWriterReaderFabric interface.
type MockEncryptionWriterReaderFabric struct {
	ctrl     *gomock.Controller
	recorder *MockEncryptionWriterReaderFabricMockRecorder
}

// MockEncryptionWriterReaderFabricMockRecorder is the mock recorder for MockEncryptionWriterReaderFabric.
type MockEncryptionWriterReaderFabricMockRecorder struct {
	mock *MockEncryptionWriterReaderFabric
}

// NewMockEncryptionWriterReaderFabric creates a new mock instance.
func NewMockEncryptionWriterReaderFabric(ctrl *gomock.Controller) *MockEncryptionWriterReaderFabric {
	mock := &MockEncryptionWriterReaderFabric{ctrl: ctrl}
	mock.recorder = &MockEncryptionWriterReaderFabricMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEncryptionWriterReaderFabric) EXPECT() *MockEncryptionWriterReaderFabricMockRecorder {
	return m.recorder
}

// CreateNewEncryptedReader mocks base method.
func (m *MockEncryptionWriterReaderFabric) CreateNewEncryptedReader(userID, dataName string, key []byte) (io.ReadCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateNewEncryptedReader", userID, dataName, key)
	ret0, _ := ret[0].(io.ReadCloser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateNewEncryptedReader indicates an expected call of CreateNewEncryptedReader.
func (mr *MockEncryptionWriterReaderFabricMockRecorder) CreateNewEncryptedReader(userID, dataName, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateNewEncryptedReader", reflect.TypeOf((*MockEncryptionWriterReaderFabric)(nil).CreateNewEncryptedReader), userID, dataName, key)
}

// CreateNewEncryptedWriter mocks base method.
func (m *MockEncryptionWriterReaderFabric) CreateNewEncryptedWriter(userID, dataName string) (io.WriteCloser, []byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateNewEncryptedWriter", userID, dataName)
	ret0, _ := ret[0].(io.WriteCloser)
	ret1, _ := ret[1].([]byte)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreateNewEncryptedWriter indicates an expected call of CreateNewEncryptedWriter.
func (mr *MockEncryptionWriterReaderFabricMockRecorder) CreateNewEncryptedWriter(userID, dataName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateNewEncryptedWriter", reflect.TypeOf((*MockEncryptionWriterReaderFabric)(nil).CreateNewEncryptedWriter), userID, dataName)
}
