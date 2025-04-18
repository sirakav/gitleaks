package rules

import (
	"github.com/sirakav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/sirakav/gitleaks/v8/cmd/generate/secrets"
	"github.com/sirakav/gitleaks/v8/config"
)

func ZendeskSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "zendesk-secret-key",
		Description: "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"zendesk"}, utils.AlphaNumeric("40"), true),
		Keywords: []string{
			"zendesk",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("zendesk", secrets.NewSecret(utils.AlphaNumeric("40")))
	return utils.Validate(r, tps, nil)
}
