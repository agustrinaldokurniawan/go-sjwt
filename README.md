# go-sjwt
Simple Golang JWT

## Installation 🚀

Activate GO111MODULE
```
go env -w GO111MODULE="on"
```

install package
```
go get -u github.com/agustrinaldokurniawan/go-sjwt
```

## Usage 💻

```
import(
        ...
        sjwt "github.com/agustrinaldokurniawan/go-sjwt"
)
```

### Set Algorithm
supported:
    SHA256 -> HS256
    
```
alg :=  "HS256"
```

### Set Payload
```c
payload := sjwt.Payload{}
payload.Iss = "login" // set issuer
payload.Aud = "www.domain.com" // set audience
payload.Exp = 3600 // set expired in second
payload.Sub = "user@email.com" // set subject
payload.Role = "admin" // set role
```

### Get Token
```c
secret := "mysecret" // change with your secret
token, err := sjwt.JWT(alg, payload, secret)
	if err != nil {
		return err
	}
  
return token
```

### Verify Token
```
role, status, errVerfify := sjwt.VerifyJWT("token")
	if errVerfify != nil {
		fmt.Println(errVerfify)
	}

	if role == "admin" {
		fmt.Println("You are admin")
	}

	if status {
		fmt.Println("Authenticated")
		fmt.Println(token)
	}
```

## Contributing ♥️
Pull request are welcome. I'm very happy if we can improve this code together 😊

## License
[MIT](https://github.com/agustrinaldokurniawan/go-sjwt/blob/main/LICENSE)
