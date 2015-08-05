package gold

import (
	"crypto/sha1"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignaturesRSA(t *testing.T) {
	privKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`)

	pubKey := []byte(`-----BEGIN RSA PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END RSA PUBLIC KEY-----`)

	pubT := "RSAPublicKey"
	pubN := "c2144346c37df21a2872f76a438d94219740b7eab3c98fe0af7d20bcfaadbc871035eb5405354775df0b824d472ad10776aac05eff6845c9cd83089260d21d4befcfba67850c47b10e7297dd504f477f79bf86cf85511e39b8125e0cad474851c3f1b1ca0fa92ff053c67c94e8b5cfb6c63270a188bed61aa9d5f21e91ac6cc9"
	pubE := "65537"

	h := `WebID-RSA source="https://deiu.me/Private/", username="https://deiu.me/profile#me", nonce="MTQzODc4MzA5NXxtS1dYcVd4bGRjVXQ2bFVEMXk2NE5KMDU1TFB3Nk9qM2FmMWduMk4tdl9tWDdvZXBtdUJSa1ZMRHE4WWZ1dUE0RlNGeDl0OGt6SGZnbkpZbW5CWE96TUxRamJ6a3xCC-Ik7gERpCBc__l2OK0DxVxyIiLTDVZ7rLIib2MNSQ==", sig="qiTKnXaXgMfGEA2LLCqhFWiB+6T9gXvLR6nO2dCvk71nBoK3MiwLxbsF83uKT81ur9SucDJ2fmjLKPbP9o7NrkYrM45rkPJsXHjbAzHDw2DftKLez5DF70HtDa1rEaUEF1mLrNMGfL4VYea5z15lNNNiDKaJpCwhgeHNB1x2qNY="`
	_toSign := `https://deiu.me/Private/https://deiu.me/profile#meMTQzODc4MzA5NXxtS1dYcVd4bGRjVXQ2bFVEMXk2NE5KMDU1TFB3Nk9qM2FmMWduMk4tdl9tWDdvZXBtdUJSa1ZMRHE4WWZ1dUE0RlNGeDl0OGt6SGZnbkpZbW5CWE96TUxRamJ6a3xCC-Ik7gERpCBc__l2OK0DxVxyIiLTDVZ7rLIib2MNSQ==`
	_sig := `qiTKnXaXgMfGEA2LLCqhFWiB+6T9gXvLR6nO2dCvk71nBoK3MiwLxbsF83uKT81ur9SucDJ2fmjLKPbP9o7NrkYrM45rkPJsXHjbAzHDw2DftKLez5DF70HtDa1rEaUEF1mLrNMGfL4VYea5z15lNNNiDKaJpCwhgeHNB1x2qNY=`
	p, err := ParseDigestAuthorizationHeader(h)
	assert.NoError(t, err)

	assert.Equal(t, _sig, p.Signature)

	parserPem, perr := ParseRSAPublicPEMKey(pubKey)
	assert.NoError(t, perr)

	parser, perr := ParseRSAPublicKeyNE(pubT, pubN, pubE)
	assert.NoError(t, perr)

	signer, err := ParseRSAPrivatePEMKey(privKey)
	assert.NoError(t, err)

	toSign := p.Source + p.Username + p.Nonce
	assert.Equal(t, _toSign, toSign)

	claim := sha1.Sum([]byte(toSign))
	signed, err := signer.Sign(claim[:])
	assert.NoError(t, err)
	b64Sig := base64.StdEncoding.EncodeToString(signed)
	assert.Equal(t, p.Signature, b64Sig)

	// println(p.Source, p.Username, p.Nonce, p.Signature)
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	assert.NoError(t, err)

	err = parser.Verify(claim[:], sig)
	assert.NoError(t, err)

	sig, err = base64.StdEncoding.DecodeString(_sig)
	assert.NoError(t, err)

	err = parserPem.Verify(claim[:], sig)
	assert.NoError(t, err)

	err = parser.Verify(claim[:], sig)
	assert.NoError(t, err)
}

func TestSignAndVerify(t *testing.T) {
	privKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`)
	pubKey := []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`)

	toSign := "some string"
	claim := sha1.Sum([]byte(toSign))

	signer, err := ParseRSAPrivatePEMKey(privKey)
	assert.NoError(t, err)

	signed, err := signer.Sign(claim[:])
	assert.NoError(t, err)

	sig := base64.URLEncoding.EncodeToString(signed)
	assert.NotEmpty(t, sig)

	parser, perr := ParseRSAPublicPEMKey(pubKey)
	assert.NoError(t, perr)

	err = parser.Verify(claim[:], signed)
	assert.NoError(t, err)

	// check with ParsePublicRSAKey
	pubT := "RSAPublicKey"
	pubN := "c2144346c37df21a2872f76a438d94219740b7eab3c98fe0af7d20bcfaadbc871035eb5405354775df0b824d472ad10776aac05eff6845c9cd83089260d21d4befcfba67850c47b10e7297dd504f477f79bf86cf85511e39b8125e0cad474851c3f1b1ca0fa92ff053c67c94e8b5cfb6c63270a188bed61aa9d5f21e91ac6cc9"
	pubE := "65537"

	parser, err = ParseRSAPublicKeyNE(pubT, pubN, pubE)
	assert.NoError(t, perr)

	err = parser.Verify(claim[:], signed)
	assert.NoError(t, err)

	// check with parse rsa.PublicKey
	signer, err = ParseRSAPrivateKey(user1k)
	assert.NoError(t, err)

	signed, err = signer.Sign(claim[:])
	assert.NoError(t, err)

	sig = base64.StdEncoding.EncodeToString(signed)
	assert.NotEmpty(t, sig)

	parser, perr = ParseRSAPublicKey(user1p)
	assert.NoError(t, perr)

	err = parser.Verify(claim[:], signed)
	assert.NoError(t, err)
}
