package lib

import (
	"fmt"
	"os/exec"

	"github.com/beego/beego/v2/core/logs"
)

func DeletePKI(ovConfigPath string, name string) error {
	//logs.Info("Lib: Deleting:", name)
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./remove.sh %s", name))
	cmd.Dir = ovConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	return nil
}

func InitPKI(ovConfigPath string, name string) error {
	//logs.Info("Lib: Runing init for:", name)
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./generate_ca_and_server_certs.sh %s", name))
	cmd.Dir = ovConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	return nil
}

func RestartContainer(ovConfigPath string, name string) error {
	//logs.Info("Lib: Restarting:", name)
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./restart.sh %s", name))
	cmd.Dir = ovConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	return nil
}
