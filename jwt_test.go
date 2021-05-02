package jwt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncB64Header(t *testing.T) {
	value := Header{}
	value.Typ = "JWT"
	value.Alg = "HS256"

	response, err := encB64Header(value)

	require.NoError(t, err)
	require.NotEmpty(t, response)
}

func TestDecB64Header(t *testing.T) {
	value := Header{}
	value.Typ = "JWT"
	value.Alg = "HS256"
	encV, errE := encB64Header(value)
	decV, errD := decB64Header(encV)

	require.NoError(t, errE)
	require.NoError(t, errD)
	require.NotEmpty(t, decV)
	require.Equal(t, value, decV)
}

func TestEncB64Payload(t *testing.T) {
	value := Payload{}
	value.Iss = "login"
	value.Aud = "www.domain.com"
	value.Exp = 3600
	value.Sub = "user@email.com"
	value.Role = "admin"

	response, err := encB64Payload(value)

	require.NoError(t, err)
	require.NotEmpty(t, response)
}

func TestDecB64Payload(t *testing.T) {
	value := Payload{}
	value.Iss = "login"
	value.Aud = "www.domain.com"
	value.Exp = 3600
	value.Sub = "user@email.com"
	value.Role = "admin"

	encV, errE := encB64Payload(value)
	decV, errD := decB64Payload(encV)

	require.NoError(t, errE)
	require.NoError(t, errD)
	require.NotEmpty(t, decV)

	require.Equal(t, value.Iss, decV.Iss)
	require.Equal(t, value.Aud, decV.Aud)
	require.Equal(t, value.Sub, decV.Sub)
	require.Equal(t, value.Role, decV.Role)
}

func TestSignature(t *testing.T) {
	valueH := Header{}
	valueH.Typ = "JWT"
	valueH.Alg = "HS256"

	encH, err := encB64Header(valueH)

	require.NoError(t, err)
	require.NotEmpty(t, encH)

	valueP := Payload{}
	valueP.Iss = "login"
	valueP.Aud = "www.domain.com"
	valueP.Exp = 3600
	valueP.Sub = "user@email.com"
	valueP.Role = "admin"

	encP, errE := encB64Payload(valueP)
	decV, errD := decB64Payload(encP)

	require.NoError(t, errE)
	require.NoError(t, errD)
	require.NotEmpty(t, decV)

	require.Equal(t, valueP.Iss, decV.Iss)
	require.Equal(t, valueP.Aud, decV.Aud)
	require.Equal(t, valueP.Sub, decV.Sub)
	require.Equal(t, valueP.Role, decV.Role)

	secret := "mysecret"

	sign, errS := Signature(encH, encP, secret)
	require.NoError(t, errS)
	require.NotEmpty(t, sign)
}

func TestJWT(t *testing.T) {
	valueP := Payload{}
	valueP.Iss = "login"
	valueP.Aud = "www.domain.com"
	valueP.Exp = 3600
	valueP.Sub = "user@email.com"
	valueP.Role = "admin"

	alg := "HS256"

	secret := "mysecret"

	jwt, errjwt := JWT(alg, valueP, secret)

	require.NoError(t, errjwt)
	require.NotEmpty(t, jwt)

	// require.Equal(t, "test", jwt)
}

func TestVerifyJWT(t *testing.T) {
	valueP := Payload{}
	valueP.Iss = "login"
	valueP.Aud = "www.domain.com"
	valueP.Exp = 3600
	valueP.Sub = "user@email.com"
	valueP.Role = "admin"

	alg := "HS256"

	secret := "mysecret"

	jwt, errjwt := JWT(alg, valueP, secret)

	require.NoError(t, errjwt)
	require.NotEmpty(t, jwt)

	role, status, errver := VerifyJWT("jwt")

	require.NoError(t, errver)
	require.Equal(t, valueP.Role, role)
	require.True(t, status)

	// require.Equal(t, "test", jwt)
}
