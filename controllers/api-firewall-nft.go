package controllers

import (
	"net/http"

	"github.com/d3vilh/openvpn-ui/lib"
)

// APIFirewallNFTController exposes nftables snapshot.
type APIFirewallNFTController struct {
	APIBaseController
}

// Snapshot returns nftables snapshot.
// @router /api/firewall/nft/snapshot [get]
func (c *APIFirewallNFTController) Snapshot() {
	info, err := lib.CollectFirewallInfo(c.Ctx.Request.Context(), lib.Config{})
	if err != nil {
		var warnings []string
		for _, w := range info.Warnings {
			warnings = append(warnings, w...)
		}
		if lib.IsFirewallPermissionError(err) {
			warnings = append(warnings, "need CAP_NET_ADMIN")
		}
		resp := map[string]interface{}{
			"error":    err.Error(),
			"warnings": warnings,
		}
		status := http.StatusInternalServerError
		if lib.IsFirewallPermissionError(err) {
			status = http.StatusForbidden
		}
		c.Ctx.Output.SetStatus(status)
		c.Data["json"] = resp
		c.ServeJSON()
		return
	}
	c.Data["json"] = info
	c.ServeJSON()
}
