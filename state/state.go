package state

import (
	"github.com/beego/beego/v2/client/orm"
	"github.com/nicesoft-labs/openvpn-ui/models"
)

const DefaultProfile = "default"

var GlobalCfg models.Settings

func GetSettings(profile string) (*models.Settings, error) {
	if profile == "" {
		profile = DefaultProfile
	}

	cfg := models.Settings{Profile: profile}
	if err := cfg.Read("Profile"); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func ListProfiles() ([]string, error) {
	var profiles []models.Settings
	_, err := orm.NewOrm().QueryTable(new(models.Settings)).All(&profiles, "Profile")
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(profiles))
	for _, p := range profiles {
		result = append(result, p.Profile)
	}

	return result, nil
}
