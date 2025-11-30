package lib

import (
	"os/exec"

	"github.com/beego/beego/v2/core/logs"
	"github.com/nicesoft-labs/openvpn-ui/state"
)

// ApplyFirewallRules triggers firewall reconfiguration based on current OpenVPN config.
func ApplyFirewallRules() error {
	cmd := exec.Command("/bin/bash", "-c",
		"cd /opt/scripts/ && ./apply-fw-rules.sh")
	cmd.Dir = state.GlobalCfg.OVConfigPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		logs.Debug(string(output))
		logs.Error(err)
		return err
	}
	logs.Info(string(output))
	return nil
}
