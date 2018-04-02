// easy_rsa_test
package easy_rsa

import (
	"testing"
)

func TestLoadKey(t *testing.T) {
	err := LoadKey(privateKeyData, publicKeyData)
	if err != nil {
		t.Error("failed to testing LoadKey, error:%v\n", err)
	}
}

func TestSignVerify(t *testing.T) {
	data := "test"
	signData, err := Sign([]byte(data))
	if err != nil {
		t.Error("failed to testing Sign, error:%v\n", err)
		return
	}

	err = Verify([]byte(data), signData)
	if err != nil {
		t.Error("failed to testing Verify, error:%v\n", err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	data := "test"
	encData, err := Encrypt([]byte(data))
	if err != nil {
		t.Error("failed to testing Encrypt, error:%v\n", err)
		return
	}

	decData, err := Decrypt(encData)
	if err != nil {
		t.Error("failed to testing Decrypt, error:%v\n", err)
		return
	}

	if string(decData) != data {
		t.Error("failed to checker decrypt data, decData:%s, srcData:%s\n", decData, data)
	}
}
