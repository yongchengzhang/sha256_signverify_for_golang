// easy_rsa
package easy_rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	privateKeyData []byte
	publicKeyData  []byte

	privateKeyObject *rsa.PrivateKey
	publicKeyObject  *rsa.PublicKey
)

func LoadKey(privateKey, publicKey []byte) error {

	priBlock, _ := pem.Decode(privateKey)
	if priBlock == nil {
		return errors.New("private key error.")
	}

	pubBlock, _ := pem.Decode(publicKey)
	if pubBlock == nil {
		return errors.New("public key error.")
	}

	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return err
	}

	pri, err := x509.ParsePKCS8PrivateKey(priBlock.Bytes)
	if err != nil {
		privateKeyObject, err = x509.ParsePKCS1PrivateKey(priBlock.Bytes)
		if err != nil {
			return err
		}
	} else {
		privateKeyObject = pri.(*rsa.PrivateKey)
	}

	publicKeyObject = pub.(*rsa.PublicKey)

	return nil
}
func Encrypt(plaintext []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKeyObject, plaintext)
}
func Decrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKeyObject, ciphertext)
}

func Sign(src []byte) ([]byte, error) {
	h := crypto.SHA256.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, privateKeyObject, crypto.SHA256, hashed)
}

func Verify(src []byte, sign []byte) error {
	h := crypto.SHA256.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKeyObject, crypto.SHA256, hashed, sign)
}

func init() {
	privateKeyData = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuSk6KkC1GjCwHiCqupMqxtBEIAKdiSCuQ7b4o31Agp8K7+SZ
GNzCPkdyBxQiB4CHEeYsehrVkAQm+z8qPQQ6ANzYezZmrbc0eYAT3rjHDmowJGkV
fL/ZHh9dvt/YFOvIxM3lfDglQjigteFnUnBVqr0FlYC2QkNHjUrynFvDfBq/G296
LX1IMVSr2sJzfBuynzQq7FrUTA3zhD55H0CF13ud3HT7OwanI2CJETpruM/6ci9a
QdlGqQR+hMAq01xheCVvmDfXX6HH23nKkLwyZcS8moQ8utsJrqE3nFxo9g5Q3PFE
uYmX4JSnXle3/0dcmq482uB3bjDfoUbYvPJJxQIDAQABAoIBAG3KcF7Vd41MCWIT
5Kg000yH+Z0xb8/7vNkSCWSHxFSvkYClf9IqNFNRcd+YpITmRTDr1rugZbm7fJHF
5nm/o9UXHpYQr9mZpFfXBfEuh3mYpWsxlDggWdFur9uaRzpAhQ+NNuHtOMqHYWP3
f5h2W5Wd902qwGeSFT9GjY0BLGzNO4qu9YMlM4hIN6uUbOIeyznOB/ZqTVdHsGCh
pOIfpUqh6nPLbPURUKZQo1Tk8lcrrx6QnTtJfrIuJmpqNRGm3ShYzBjWeNjnBGkH
twrmYjs+B8zEDvE3w8Z+1SG2RO4w1xunTjG3Q7aG/eDI2Txo0iDD2uKgiCbdbFhX
UCfekoECgYEA8nlTnJ6QgIiEjn6xxKoU4/UyuxsJnKqqCPxUQFRpuwqNDFhsh3Tg
hRVd4eZWlasuLilZhsVIgw11lZjeFwWAh1KTk7sVIyvYVnQGSkea3HE9YB+XpaR+
s8O9sg/lIQcfP9iuuso39aDMl7I9FR2d9DRZP8Bci+95L/1kdJwVMF0CgYEAw31w
KTl6IqqARX5Y4a/7tGNga6a4F93253+Z3h68tWN0PWsec0vkRUMZYhCrPT41vmi4
wyZM+etRMR6UDjE6l4Kg7b7QosMVpDViKWOhQy68hH0qOiOSMMYqJRL3JR7hijOf
hPKhJtXpZH9lEIUM/3Wnu68cykU1ke5UA2zyiIkCgYAgIvBv+5wPTQi0khohhKFM
LT1SCx1VBFGQ61CHTijNP3K+RiHsOhNf0BsnS44CPDPcrmJNOGyJ4gjJkP8uce49
ATbKB6ufg7oiizIiOidOPDv0N3uz2n9od/L2XKDzpawAnElcPFz6UxuKp3btC4XZ
ze5eQrKBYXXgZGciBWXRiQKBgDEYcLG5wKWyIlLRn2rWsqUkDBQdI8DCuv56ul7h
Y00+s/O00knsdmC6sEZDn23bEM5IKJbCKLTfV125qz9BN9DTOq1arbUiv22lBokU
f2yK8Udo09EUG+Pp8K2s7KrC7auyuU4/TR+eu2XE5NHYSGJj3wMwwE9AQGrs6uaN
Vv/ZAoGAKD6ae7z9pRIFw2nmezhd5GAMVler09yzslSSGBE82As6IkQmggf0BWMW
eTPdnsWBYkAuHjpr4rcIDelWeDuWrZv8IhiaBuEr1JZwS0/AZAPduytTGYEZLMpu
fdVhtbd0fxFvTGlpbZAbKerJ5t00tclwvVD4Bwo9SEJwjLv5HsY=
-----END RSA PRIVATE KEY-----
`)
	publicKeyData = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuSk6KkC1GjCwHiCqupMq
xtBEIAKdiSCuQ7b4o31Agp8K7+SZGNzCPkdyBxQiB4CHEeYsehrVkAQm+z8qPQQ6
ANzYezZmrbc0eYAT3rjHDmowJGkVfL/ZHh9dvt/YFOvIxM3lfDglQjigteFnUnBV
qr0FlYC2QkNHjUrynFvDfBq/G296LX1IMVSr2sJzfBuynzQq7FrUTA3zhD55H0CF
13ud3HT7OwanI2CJETpruM/6ci9aQdlGqQR+hMAq01xheCVvmDfXX6HH23nKkLwy
ZcS8moQ8utsJrqE3nFxo9g5Q3PFEuYmX4JSnXle3/0dcmq482uB3bjDfoUbYvPJJ
xQIDAQAB
-----END PUBLIC KEY-----
`)
	LoadKey(privateKeyData, publicKeyData)
}
