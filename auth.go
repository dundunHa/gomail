package gomail

import (
	"bytes"
	"errors"
	"fmt"
	"net/smtp"
)

// loginAuth is an smtp.Auth that implements the LOGIN authentication mechanism.
type loginAuth struct {
	username string
	password string
	host     string
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// if !server.TLS {
	// 	advertised := false
	// 	for _, mechanism := range server.Auth {
	// 		if mechanism == "LOGIN" {
	// 			advertised = true
	// 			break
	// 		}
	// 	}
	// 	if !advertised {
	// 		return "", nil, errors.New("gomail: unencrypted connection")
	// 	}
	// }
	
	if server.Name != a.host {
		return "", nil, errors.New("gomail: wrong host name")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}

	switch {
	case bytes.Equal(fromServer, []byte("username:")):
		return []byte(a.username), nil
	case bytes.Equal(fromServer, []byte("password:")):
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("gomail: unexpected server challenge: %s", fromServer)
	}
}


type plainAuth struct {
	identity, username, password string
	host                         string
}

func (a *plainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *plainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		// We've already sent everything.
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}
