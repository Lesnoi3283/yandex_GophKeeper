package hashiCorpVault

import (
	"encoding/base64"
	"fmt"
	"path"

	"github.com/hashicorp/vault/api"
)

// Paths where HashiCorp will store data.
const (
	bankCardPath         = "bank_cards"
	loginAndPasswordPath = "login_and_password"
	textDataPath         = "text_data"
	binDataPath          = "bin_data"
	// keyForAKey IS NOT A PATH!!!!
	keyForAKey = "key"
)

// HashiCorpVault implements KeyKeeper interface and can store keys safe.
// It follows PCI DSS 4.0.
type HashiCorpVault struct {
	client *api.Client
}

// NewHashiCorpVault creates new HashiCorpVault.
func NewHashiCorpVault(address string, token string) (*HashiCorpVault, error) {
	conf := api.DefaultConfig()
	conf.Address = address

	client, err := api.NewClient(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault API client: %w", err)
	}

	client.SetToken(token)

	return &HashiCorpVault{client: client}, nil
}

// SetKey saves key to the path.
func (v *HashiCorpVault) SetKey(path string, key string) error {
	keyBase64 := base64.StdEncoding.EncodeToString([]byte(key))

	_, err := v.client.Logical().Write(path, map[string]interface{}{keyForAKey: keyBase64})
	if err != nil {
		return fmt.Errorf("failed to set key, err: %v", err)
	}

	return nil
}

// GetKey reads a key from path.
func (v *HashiCorpVault) GetKey(path string) (string, error) {

	//get data
	s, err := v.client.Logical().Read(path)
	if err != nil {
		return "", fmt.Errorf("failed to read data, err: %v", err)
	}
	if s == nil {
		return "", fmt.Errorf("no data found at path %s", path)
	}

	data, ok := s.Data[keyForAKey]
	if !ok {
		return "", fmt.Errorf("key was not found")
	}

	//parse to string
	keyStr, ok := data.(string)
	if !ok {
		return "", fmt.Errorf("key is not a string")
	}

	unbase64, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode key from base64, err: %v", err)
	}

	return string(unbase64), nil
}

func (v *HashiCorpVault) SetBankCardKey(userID, dataID, key string) error {
	fullPath := path.Join(bankCardPath, userID, dataID)
	return v.SetKey(fullPath, key)
}

func (v *HashiCorpVault) GetBankCardKey(userID, dataID string) (string, error) {
	fullPath := path.Join(bankCardPath, userID, dataID)
	return v.GetKey(fullPath)
}

func (v *HashiCorpVault) SetTextDataKey(userID, dataID, key string) error {
	fullPath := path.Join(textDataPath, userID, dataID)
	return v.SetKey(fullPath, key)
}

func (v *HashiCorpVault) GetTextDataKey(userID, dataID string) (string, error) {
	fullPath := path.Join(textDataPath, userID, dataID)
	return v.GetKey(fullPath)
}

func (v *HashiCorpVault) SetLoginAndPasswordKey(userID, dataID, key string) error {
	fullPath := path.Join(loginAndPasswordPath, userID, dataID)
	return v.SetKey(fullPath, key)
}

func (v *HashiCorpVault) GetLoginAndPasswordKey(userID, dataID string) (string, error) {
	fullPath := path.Join(loginAndPasswordPath, userID, dataID)
	return v.GetKey(fullPath)
}

func (v *HashiCorpVault) SetBinaryDataKey(userID, dataID, key string) error {
	fullPath := path.Join(binDataPath, userID, dataID)
	return v.SetKey(fullPath, key)
}

func (v *HashiCorpVault) GetBinaryDataKey(userID, dataID string) (string, error) {
	fullPath := path.Join(binDataPath, userID, dataID)
	return v.GetKey(fullPath)
}
