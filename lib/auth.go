package lib

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"github.com/go-ldap/ldap/v3"
	"github.com/nicesoft-labs/openvpn-ui/models"
	"gopkg.in/hlandau/passlib.v1"
)

const (
	authTypeLDAP = "ldap"
	tcpProtocol  = "tcp"
)

var authError = errors.New("invalid login or password")

func Authenticate(login, password, authType string) (*models.User, error) {
	logs.Info("auth type: ", authType)

	switch authType {
	case authTypeLDAP:
		return authenticateLdap(login, password)
	default:
		return authenticateSimple(login, password)
	}
}

func authenticateSimple(login, password string) (*models.User, error) {
	user := &models.User{Login: login}
	err := user.Read("Login")
	if err != nil {
		logs.Error(err)
		return nil, authError
	}
	if user.Id < 1 {
		logs.Error(authError)
		return nil, authError
	}
	if _, err := passlib.Verify(password, user.Password); err != nil {
		logs.Error(err)
		return nil, authError
	}
	return user, nil
}

type ldapConfig struct {
	address    string
	transport  string
	bindDN     string
	skipVerify bool
}

func loadLdapConfig() (*ldapConfig, error) {
	address, err := web.AppConfig.String("LdapAddress")
	if err != nil {
		return nil, fmt.Errorf("load LDAP address: %w", err)
	}

	transport, err := web.AppConfig.String("LdapTransport")
	if err != nil {
		return nil, fmt.Errorf("load LDAP transport: %w", err)
	}

	bindDN, err := web.AppConfig.String("LdapBindDn")
	if err != nil {
		return nil, fmt.Errorf("load LDAP bind DN: %w", err)
	}

	skipVerify, err := web.AppConfig.Bool("LdapInsecureSkipVerify")
	if err != nil {
		return nil, fmt.Errorf("load LDAP insecure skip verify flag: %w", err)
	}

	return &ldapConfig{
		address:    address,
		transport:  transport,
		bindDN:     bindDN,
		skipVerify: skipVerify,
	}, nil
}

func authenticateLdap(login, password string) (*models.User, error) {
	config, err := loadLdapConfig()
	if err != nil {
		logs.Error("LDAP config:", err)
		return nil, authError
	}

	connection, err := dialLdap(config)
	if err != nil {
		logs.Error("LDAP Dial:", err)
		return nil, authError
	}
	defer connection.Close()

	if err := startTLSIfNeeded(connection, config); err != nil {
		logs.Error("LDAP Start TLS:", err)
		return nil, authError
	}

	err = connection.Bind(fmt.Sprintf(config.bindDN, login), password)
	if err != nil {
		logs.Error("LDAP Bind:", err)
		return nil, authError
	}

	user := &models.User{Login: login}
	err = user.Read("Login")
	if err == orm.ErrNoRows {
		err = user.Insert()
	}
	if err != nil {
		logs.Error(err)
		return nil, authError
	}

	return user, nil
}

func dialLdap(config *ldapConfig) (*ldap.Conn, error) {
	switch config.transport {
	case "tls":
		return ldap.DialTLS(tcpProtocol, config.address, &tls.Config{InsecureSkipVerify: config.skipVerify})
	default:
		return ldap.Dial(tcpProtocol, config.address)
	}
}

func startTLSIfNeeded(connection *ldap.Conn, config *ldapConfig) error {
	if config.transport != "starttls" {
		return nil
	}

	return connection.StartTLS(&tls.Config{InsecureSkipVerify: config.skipVerify})
}

// GetUserByEmail retrieves a user by their email address
func GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{Email: email}
	err := user.Read("Email")
	if err != nil {
		if err == orm.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return user, nil
}
