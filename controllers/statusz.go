package controllers

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/models"
)

type StatuszController struct {
	BaseController
}

func (c *StatuszController) NestPrepare() {
	if !c.IsLogin {
		c.CustomAbort(401, "unauthorized")
	}
}

// Statusz responds with the latest UI snapshot stored in the database.
func (c *StatuszController) Statusz() {
	payload, updatedAt, err := models.GetUISnapshot()
	if err != nil || payload == "" {
		c.Ctx.Output.SetStatus(503)
		c.Data["json"] = map[string]string{"error": "no snapshot"}
		_ = c.ServeJSON()
		return
	}

	setETagFromTime(c, updatedAt)
	c.Ctx.Output.Header("Cache-Control", "no-store, must-revalidate")
	c.Ctx.Output.Header("Content-Type", "application/json")
	_ = c.Ctx.Output.Body([]byte(payload))
}

// Metrics responds with only the metrics section from the stored snapshot.
func (c *StatuszController) Metrics() {
	payload, updatedAt, err := models.GetUISnapshot()
	if err != nil || payload == "" {
		c.Ctx.Output.SetStatus(503)
		c.Data["json"] = map[string]string{"error": "no snapshot"}
		_ = c.ServeJSON()
		return
	}

	var snap struct {
		Metrics json.RawMessage `json:"metrics"`
	}
	if err := json.Unmarshal([]byte(payload), &snap); err != nil {
		logs.Warn("metrics snapshot unmarshal: %v", err)
		c.CustomAbort(500, "invalid snapshot")
		return
	}

	setETagFromTime(c, updatedAt)
	c.Ctx.Output.Header("Cache-Control", "no-store, must-revalidate")
	c.Ctx.Output.Header("Content-Type", "application/json")
	if snap.Metrics == nil {
		snap.Metrics = []byte("null")
	}
	_ = c.Ctx.Output.Body(snap.Metrics)
}

func setETagFromTime(c *StatuszController, ts interface{}) {
	var data []byte
	switch v := ts.(type) {
	case string:
		data = []byte(v)
	default:
		data = []byte(fmt.Sprint(v))
	}
	hash := sha256.Sum256(data)
	c.Ctx.Output.Header("ETag", fmt.Sprintf("\"%x\"", hash))
}
