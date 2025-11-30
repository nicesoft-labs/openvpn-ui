package models

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	clientconfig "github.com/d3vilh/openvpn-server-config/client/client-config"
	easyrsaconfig "github.com/d3vilh/openvpn-server-config/easyrsa/config"
	"github.com/d3vilh/openvpn-server-config/server/config"
	"gopkg.in/hlandau/passlib.v1"
)

func InitDB() {
	err := orm.RegisterDriver("sqlite3", orm.DRSqlite)
	if err != nil {
		panic(err)
	}
	dbPath, err := web.AppConfig.String("dbPath")
	if err != nil {
		panic(err)
	}
	dbSource := "file:" + dbPath

	err = orm.RegisterDataBase("default", "sqlite3", dbSource)
	if err != nil {
		panic(err)
	}
	orm.Debug = true
	orm.RegisterModel(
		new(User),
		new(Settings),
		new(OVConfig),
		new(OVClientConfig),
		new(EasyRSAConfig),
	)

	err = orm.RunSyncdb("default", false, true)
	if err != nil {
		logs.Error(err)
		return
	}
}

func CreateDefaultUsers() {
	hash, err := passlib.Hash(os.Getenv("OPENVPN_ADMIN_PASSWORD"))
	if err != nil {
		logs.Error("Unable to hash password", err)
	}
	user := User{
		Id:       1,
		Login:    os.Getenv("OPENVPN_ADMIN_USERNAME"),
		IsAdmin:  true,
		Name:     "Administrator",
		Email:    "root@localhost",
		Password: hash,
	}
	o := orm.NewOrm()
	if created, _, err := o.ReadOrCreate(&user, "Name"); err == nil {
		if created {
			logs.Info("Default admin account created")
		} else {
			logs.Debug(user)
		}
	}
}

func CreateDefaultSettings() (*Settings, error) {
	miAddress, err := web.AppConfig.String("OpenVpnManagementAddress")
	if err != nil {
		return nil, err
	}
	miNetwork, err := web.AppConfig.String("OpenVpnManagementNetwork")
	if err != nil {
		return nil, err
	}
	ovConfigPath, err := web.AppConfig.String("OpenVpnPath")
	if err != nil {
		return nil, err
	}

	easyRSAPath, err := web.AppConfig.String("EasyRsaPath")
	if err != nil {
		return nil, err
	}

	s := Settings{
		Profile:      "default",
		MIAddress:    miAddress,
		MINetwork:    miNetwork,
		OVConfigPath: ovConfigPath,
		EasyRSAPath:  easyRSAPath,
		//	ServerAddress:     serverAddress,
		//	OpenVpnServerPort: serverPort,
	}

	o := orm.NewOrm()
	if created, _, err := o.ReadOrCreate(&s, "Profile"); err == nil {
		if created {
			logs.Info("New settings profile created")
		} else {
			logs.Debug(s)
		}
		return &s, nil
	} else {
		return nil, err
	}
}

func CreateDefaultOVConfig(configDir string, ovConfigPath string, address string, network string, profile string) {
	if profile == "" {
		profile = "default"
	}

	if err := ensureInstanceDirectories(ovConfigPath, ""); err != nil {
		logs.Error(err)
		return
	}

	c := OVConfig{
		Profile: profile,
		Config: config.Config{
			FuncMode:                 0, // 0 = standard authentication (cert, cert + password), 1 = 2FA authentication (cert + OTP)
			Management:               fmt.Sprintf("%s %s", address, network),
			ScriptSecurity:           "",
			UserPassVerify:           "",
			Device:                   "tun",
			Port:                     1194,
			Proto:                    "udp",
			OVConfigTopology:         "subnet",
			Keepalive:                "10 120",
			MaxClients:               100,
			OVConfigUser:             "nobody",
			OVConfigGroup:            "nogroup",
			OVConfigClientConfigDir:  filepath.Join(ovConfigPath, "staticclients"),
			IfconfigPoolPersist:      "pki/ipp.txt",
			Ca:                       "pki/ca.crt",
			Cert:                     "pki/issued/server.crt",
			Key:                      "pki/private/server.key",
			Crl:                      "pki/crl.pem",
			Dh:                       "pki/dh.pem",
			TLSControlChannel:        "tls-crypt pki/ta.key",
			TLSMinVersion:            "tls-version-min 1.2",
			TLSRemoteCert:            "remote-cert-tls client",
			Cipher:                   "kuznyechik-cbc",
			OVConfigNcpCiphers:       "kuznyechik-cbc",
			Auth:                     "id-tc26-gost3411-12-256",
			Server:                   "server 10.0.70.0 255.255.255.0",
			Route:                    "route 10.0.71.0 255.255.255.0",
			PushRoute:                "push \"route 10.0.60.0 255.255.255.0\"",
			DNSServer1:               "push \"dhcp-option DNS 77.88.8.8\"",
			DNSServer2:               "push \"dhcp-option DNS 77.88.8.1\"",
			RedirectGW:               "push \"redirect-gateway def1 bypass-dhcp\"",
			OVConfigLogfile:          "/var/log/openvpn/openvpn.log",
			OVConfigLogVerbose:       3,
			OVConfigStatusLog:        "/var/log/openvpn/openvpn-status.log",
			OVConfigStatusLogVersion: 2,
			CustomOptOne:             "# Custom Option One",
			CustomOptTwo:             "# Custom Option Two\n# client-to-client",
			CustomOptThree:           "# Custom Option Three\n# push \"route 0.0.0.0 255.255.255.255 net_gateway\"\n# push block-outside-dns",
		},
	}
	o := orm.NewOrm()
	if created, _, err := o.ReadOrCreate(&c, "Profile"); err == nil {
		if created {
			logs.Info("New settings profile created")
		} else {
			logs.Debug(c)
		}
		serverConfig := filepath.Join(ovConfigPath, "server.conf")
		if _, err = os.Stat(serverConfig); os.IsNotExist(err) {
			if err = config.SaveToFile(filepath.Join(configDir, "openvpn-server-config.tpl"), c.Config, serverConfig); err != nil {
				logs.Error(err)
			}
		}
	} else {
		logs.Error(err)
	}
}

func CreateDefaultOVClientConfig(configDir string, ovConfigPath string, address string, network string, profile string) {
	if profile == "" {
		profile = "default"
	}

	if err := ensureInstanceDirectories(ovConfigPath, ""); err != nil {
		logs.Error(err)
		return
	}

	c := OVClientConfig{
		Profile: profile,
		Config: clientconfig.Config{
			FuncMode:          0, // 0 = standard authentication (cert, cert + password), 1 = 2FA authentication (cert + OTP)
			Device:            "tun",
			Port:              1194,
			Proto:             "udp",
			ServerAddress:     "127.0.0.1",
			OpenVpnServerPort: "1194",
			ResolveRetry:      "resolv-retry infinite",
			OVClientUser:      "nobody",
			OVClientGroup:     "nogroup",
			PersistTun:        "persist-tun",
			PersistKey:        "persist-key",
			RemoteCertTLS:     "remote-cert-tls server",
			Cipher:            "kuznyechik-cbc",
			RedirectGateway:   "redirect-gateway def1",
			Auth:              "id-tc26-gost3411-12-256",
			AuthNoCache:       "auth-nocache",
			TlsClient:         "tls-client",
			Verbose:           "3",
			AuthUserPass:      "",                 // "auth-user-pass" when 2fa
			TFAIssuer:         "MFA%20OpenVPN-UI", // 2FA issuer
			CustomConfOne:     "#Custom Option One",
			CustomConfTwo:     "#Custom Option Two",
			CustomConfThree:   "#Custom Option Three",
		},
	}
	o := orm.NewOrm()
	if created, _, err := o.ReadOrCreate(&c, "Profile"); err == nil {
		if created {
			logs.Info("New settings profile created")
		} else {
			logs.Debug(c)
		}
		clientConfig := filepath.Join(ovConfigPath, "config/client.conf")
		if _, err = os.Stat(clientConfig); os.IsNotExist(err) {
			if err = clientconfig.SaveToFile(filepath.Join(configDir, "openvpn-client-config.tpl"), c.Config, clientConfig); err != nil {
				logs.Error(err)
			}
		}
	} else {
		logs.Error(err)
	}
}

func CreateDefaultEasyRSAConfig(configDir string, easyRSAPath string, address string, network string, profile string) {
	if profile == "" {
		profile = "default"
	}

	if err := ensureInstanceDirectories("", easyRSAPath); err != nil {
		logs.Error(err)
		return
	}

	c := EasyRSAConfig{
		Profile: profile,
		Config: easyrsaconfig.Config{
			EasyRSADN:          "org",
			EasyRSAReqCountry:  "RU",
			EasyRSAReqProvince: "MOSCOW",
			EasyRSAReqCity:     "MOSCOW",
			EasyRSAReqOrg:      "NiceSOFT",
			EasyRSAReqEmail:    "info@ncsgp.ru",
			EasyRSAReqOu:       "IT",
			EasyRSAReqCn:       "server",
			EasyRSAKeySize:     2048,
			EasyRSACaExpire:    3650,
			EasyRSACertExpire:  825,
			EasyRSACertRenew:   30,
			EasyRSACrlDays:     180,
		},
	}
	o := orm.NewOrm()
	if created, _, err := o.ReadOrCreate(&c, "Profile"); err == nil {
		if created {
			logs.Info("New settings profile created")
		} else {
			logs.Debug(c)
		}
		easyRSAConfig := filepath.Join(easyRSAPath, "pki/vars")
		if _, err = os.Stat(easyRSAConfig); os.IsNotExist(err) {
			if err = easyrsaconfig.SaveToFile(filepath.Join(configDir, "easyrsa-vars.tpl"), c.Config, easyRSAConfig); err != nil {
				logs.Error(err)
			}
		}
	} else {
		logs.Error(err)
	}
}

func ensureInstanceDirectories(ovConfigPath string, easyRSAPath string) error {
	paths := make([]string, 0)

	if ovConfigPath != "" {
		paths = append(paths,
			ovConfigPath,
			filepath.Join(ovConfigPath, "clients"),
			filepath.Join(ovConfigPath, "config"),
			filepath.Join(ovConfigPath, "staticclients"),
			filepath.Join(ovConfigPath, "pki"),
			filepath.Join(ovConfigPath, "pki", "issued"),
			filepath.Join(ovConfigPath, "pki", "private"),
			filepath.Join(ovConfigPath, "pki", "crl"),
			filepath.Join(ovConfigPath, "pki", "reqs"),
		)
	}

	if easyRSAPath != "" {
		paths = append(paths,
			easyRSAPath,
			filepath.Join(easyRSAPath, "pki"),
		)
	}

	for _, path := range paths {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("creating instance directory %s: %w", path, err)
		}
	}

	return nil
}

func sanitizeProfileName(profile string) string {
	clean := strings.TrimSpace(profile)
	clean = strings.ReplaceAll(clean, "..", "")
	clean = strings.ReplaceAll(clean, string(os.PathSeparator), "-")

	if clean == "" {
		return "default"
	}

	return clean
}

func ensureProfilePath(basePath, profile string) (string, error) {
	if basePath == "" {
		return "", errors.New("base path for instance is required")
	}

	cleanBase := filepath.Clean(basePath)
	cleanProfile := sanitizeProfileName(profile)

	if filepath.Base(cleanBase) == cleanProfile {
		return cleanBase, nil
	}

	return filepath.Join(cleanBase, cleanProfile), nil
}

func ensureUniqueInstancePath(path string) string {
	candidate := path
	idx := 1

	for pathTaken(candidate) {
		candidate = fmt.Sprintf("%s-%d", path, idx)
		idx++
	}

	return candidate
}

func pathTaken(path string) bool {
	if path == "" {
		return false
	}

	if _, err := os.Stat(path); err == nil {
		return true
	}

	o := orm.NewOrm()
	if o.QueryTable(new(Settings)).Filter("OVConfigPath", path).Exist() {
		return true
	}

	return o.QueryTable(new(Settings)).Filter("EasyRSAPath", path).Exist()
}

func PrepareInstanceSettings(settings *Settings, defaultOVPath, defaultEasyRSAPath string) error {
	if settings == nil {
		return errors.New("settings cannot be nil")
	}

	settings.Profile = sanitizeProfileName(settings.Profile)

	ovPath, err := ensureProfilePath(firstNonEmpty(settings.OVConfigPath, defaultOVPath), settings.Profile)
	if err != nil {
		return err
	}
	easyRSAPath, err := ensureProfilePath(firstNonEmpty(settings.EasyRSAPath, defaultEasyRSAPath), settings.Profile)
	if err != nil {
		return err
	}

	settings.OVConfigPath = ensureUniqueInstancePath(ovPath)
	settings.EasyRSAPath = ensureUniqueInstancePath(easyRSAPath)

	return ensureInstanceDirectories(settings.OVConfigPath, settings.EasyRSAPath)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

func EnsureProfileConfigs(configDir string, settings *Settings) {
	if err := ensureInstanceDirectories(settings.OVConfigPath, settings.EasyRSAPath); err != nil {
		logs.Error(err)
	}
	CreateDefaultOVConfig(configDir, settings.OVConfigPath, settings.MIAddress, settings.MINetwork, settings.Profile)
	CreateDefaultOVClientConfig(configDir, settings.OVConfigPath, settings.MIAddress, settings.MINetwork, settings.Profile)
	CreateDefaultEasyRSAConfig(configDir, settings.EasyRSAPath, settings.MIAddress, settings.MINetwork, settings.Profile)
}
