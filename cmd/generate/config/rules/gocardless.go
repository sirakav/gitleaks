package rules

import (
	"github.com/sirakav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/sirakav/gitleaks/v8/cmd/generate/secrets"
	"github.com/sirakav/gitleaks/v8/config"
)

func GoCardless() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gocardless-api-token",
		Description: "Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"gocardless"}, `live_(?i)[a-z0-9\-_=]{40}`, true),

		Keywords: []string{
			"live_",
			"gocardless",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("gocardless", "live_"+secrets.NewSecret(utils.AlphaNumericExtended("40")))
	return utils.Validate(r, tps, nil)
}
