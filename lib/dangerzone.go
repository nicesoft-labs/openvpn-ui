package lib

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/state"
)

type ArtifactStatus struct {
	Name   string
	Path   string
	Exists bool
}

type PKIStatus struct {
	Vars      ArtifactStatus
	CRL       ArtifactStatus
	PKIConfig ArtifactStatus
	CA        ArtifactStatus
	Server    ArtifactStatus
	DH        ArtifactStatus
	TA        ArtifactStatus
}

func DeletePKI(name string) error {
	//logs.Info("Lib: Deleting:", name)
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./remove.sh %s", name))
	cmd.Dir = state.GlobalCfg.OVConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	return nil
}

func InitPKI(name string) error {
	//logs.Info("Lib: Runing init for:", name)
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./generate_ca_and_server_certs.sh %s", name))
	cmd.Dir = state.GlobalCfg.OVConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	return nil
}

func RestartContainer(name string) error {
	//logs.Info("Lib: Restarting:", name)
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./restart.sh %s", name))
	cmd.Dir = state.GlobalCfg.OVConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	return nil
}

func GetPKIStatus() (PKIStatus, error) {
	easyRSAPath := state.GlobalCfg.EasyRSAPath
	ovpnPath := state.GlobalCfg.OVConfigPath

	if easyRSAPath == "" || ovpnPath == "" {
		return PKIStatus{}, fmt.Errorf("EasyRSAPath or OVConfigPath is empty")
	}

	check := func(path string) bool {
		if path == "" {
			return false
		}

		if stat, err := os.Stat(path); err == nil {
			return !stat.IsDir()
		}

		return false
	}

	status := PKIStatus{
		Vars: ArtifactStatus{
			Name: "EasyRSA VARs",
			Path: filepath.Join(easyRSAPath, "pki", "vars"),
		},
		CRL: ArtifactStatus{
			Name: "CRL",
			Path: filepath.Join(easyRSAPath, "pki", "crl.pem"),
		},
		PKIConfig: ArtifactStatus{
			Name: "PKI",
			Path: filepath.Join(easyRSAPath, "openssl-easyrsa.cnf"),
		},
		CA: ArtifactStatus{
			Name: "CA",
			Path: filepath.Join(ovpnPath, "pki", "ca.crt"),
		},
		Server: ArtifactStatus{
			Name: "Server certificate",
			Path: filepath.Join(ovpnPath, "pki", "issued", "server.crt"),
		},
		DH: ArtifactStatus{
			Name: "DH",
			Path: filepath.Join(ovpnPath, "pki", "dh.pem"),
		},
		TA: ArtifactStatus{
			Name: "TA",
			Path: filepath.Join(ovpnPath, "pki", "ta.key"),
		},
	}

	status.Vars.Exists = check(status.Vars.Path)
	status.CRL.Exists = check(status.CRL.Path)
	status.PKIConfig.Exists = check(status.PKIConfig.Path)
	status.CA.Exists = check(status.CA.Path)
	status.Server.Exists = check(status.Server.Path)
	status.DH.Exists = check(status.DH.Path)
	status.TA.Exists = check(status.TA.Path)

	return status, nil
}
