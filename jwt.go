package jwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Header struct {
	Typ string
	Alg string
}

type Payload struct {
	Iss  string
	Iat  int64
	Exp  int64
	Aud  string
	Sub  string
	Role string
}

func encB64Header(v Header) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	encValue := base64.StdEncoding.EncodeToString(b)
	return encValue, nil
}

func decB64Header(v string) (Header, error) {
	decValue, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return Header{}, err
	}

	var h Header
	err2 := json.Unmarshal(decValue, &h)
	if err2 != nil {
		return Header{}, nil
	}
	return h, nil
}

func encB64Payload(v Payload) (string, error) {
	v.Iat = time.Now().UnixNano()
	v.Exp = time.Now().Add(time.Second * time.Duration(v.Exp)).UnixNano()

	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	encValue := base64.StdEncoding.EncodeToString(b)
	return encValue, nil
}

func decB64Payload(v string) (Payload, error) {
	decValue, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return Payload{}, err
	}

	var p Payload
	err2 := json.Unmarshal(decValue, &p)
	if err2 != nil {
		return Payload{}, nil
	}
	return p, nil
}

func Signature(h string, p string, secret string) (string, error) {
	str := h + "." + p

	decH, errDecH := decB64Header(h)
	if errDecH != nil {
		return "", errDecH
	}

	switch decH.Alg {
	case "HS256":
		h := sha256.New()
		h.Write([]byte(str))
		return hex.EncodeToString(h.Sum(nil)), nil
	default:
		return "", errors.New("unsupport algorithm")
	}
}

func JWT(alg string, p Payload, secret string) (string, error) {
	valueH := Header{}
	valueH.Typ = "JWT"
	valueH.Alg = alg

	encH, errH := encB64Header(valueH)
	if errH != nil {
		return "", errH
	}

	encP, errP := encB64Payload(p)
	if errP != nil {
		return "", errP
	}

	sign, errS := Signature(encH, encP, secret)
	if errS != nil {
		return "", errS
	}

	signV := encH + "." + encP + "." + sign
	return signV, nil
}

func VerifyJWT(v string) (string, bool, error) {
	splitString := strings.Split(v, ".")

	decP, errD := decB64Payload(splitString[1])
	if errD != nil {
		return "", false, errD
	}

	if time.Unix(0, decP.Exp).Before(time.Now()) {
		return "", false, errors.New("token expired")
	}

	return decP.Role, true, nil
}
