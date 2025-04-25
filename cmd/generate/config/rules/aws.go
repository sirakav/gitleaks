package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func AWS() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "aws-access-token",
		Description: "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.",
		Regex:       regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`),
		Entropy:     3,
		Keywords: []string{
			// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
			"A3T",  // todo: might not be a valid AWS token
			"AKIA", // Access key
			"ASIA", // Temporary (AWS STS) access key
			"ABIA", // AWS STS service bearer token
			"ACCA", // Context-specific credential
		},
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`.+EXAMPLE$`),
				},
			},
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("AWS", "AKIALALEMEL33243OLIB") // gitleaks:allow
	// current AWS tokens cannot contain [0,1,8,9], so their entropy is slightly lower than expected.
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "AKIA"+secrets.NewSecret("[A-Z2-7]{16}"))...)
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "ASIA"+secrets.NewSecret("[A-Z2-7]{16}"))...)
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "ABIA"+secrets.NewSecret("[A-Z2-7]{16}"))...)
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "ACCA"+secrets.NewSecret("[A-Z2-7]{16}"))...)
	fps := []string{
		`key = AKIAXXXXXXXXXXXXXXXX`,           // Low entropy
		`aws_access_key: AKIAIOSFODNN7EXAMPLE`, // Placeholder
		`msgstr "Näytä asiakirjamallikansio."`, // Lowercase
		`TODAYINASIAASACKOFRICEFELLOVER`,       // wrong length
		`CTTCATAGGGTTCACGCTGTGTAAT-ACG--CCTGAGGC-CACA-AGGGGACTTCAGCAACCGTCGGG-GATTC-ATTGCCA-A--TGGAAGCAATC-TA-TGGGTTA-TCGCGGAGTCCGCAAAGACGGCCAGTATG-AAGCAGATTTCGCAC-CAATGTGACTGCATTTCGTG-ATCGGGGTAAGTA-TC-GCCGATTC-GC--CCGTCCA-AGT-CGAAG-TA--GGCAATATAAAGCTGC-CATTGCCGAAGCTATCTCGCTA-TACTTGAT-AATCGGCGG-TAG-CACAG-GTCGCAGTATCG-AC-T--AGG-CCTCTCAAAAGTT-GGGTCCCGGCCTCTGGGAAAAACACCTCT-A-AGCGTCAATCAGCTCGGTTTCGCATATTA-TGATATCCCCCGTTGACCAATTGA--TAGTACCCGAGCTTACCGTCGG-ATTCTGGAGTCTT-ATGAGGTTACCGACGA-CGCAGTACCATAAGT-GCGCAATTTGACTGTTCCCGTCGAGTAACCA-AGCTTTGCTCA-CCGGGATGCGCGCCGATGTGACCAGGGGGCGCATGTTACATTGAC-A-GCTGGATCATGTTATGAC-GTGGGTC-ATGCTAAAAGCCTAAAGGACGGT-GCATTAGTAT-TACCGGGACCTCATATCAATGCGCTCGCTAGTTCCTCTTCTCTTGATAACGTATATGCGTCAGGCGCCCGTCCGCCTCCAATACGTG-ACAACGTC-AGTACTGAGCCTC--AA-ACATCGTCTTGTTCG-CC-TACAAAGGATCGGTAGAAAACTCAATATTCGGGTATAAGGTCGTAGGAAGTGTGTCGCCCAGGGCCG-CTAGA-AGCGCACACAAGCG-CTCCTGTCAAGGAGTTG-GTGAAAA-ATGAAC--GACT-ATTGCGTCAC--CTACCTCT-AAGTTTTT-GACAATTTCATGGACGAATTGA-AGCGTCCACAAGCATCTGCCGTAGATATGCGGTAGGTTTTTACATATG-TCACTGCAGAGTCACGGACA-CACATCGCTGTCAAAATGCTCGTACCTAGT-GT-TTGCGATCCCCC-GCGGCATTA-TCTTTTGAACCCTCGTCCCTGTGG-CTCTGATGATTGAG-GTCTGTA-TTCCCTCGTTGTGGGGGGATTGGACCTT-TGTATAGGTTCTTTAACCG-ATGGGGGGCCG--ATCGA-A-TA-TGCTCCTGTTTGCCCCGAACCTT-ACCTCGG-TCCAGACA-CTAAGAAAAACCCC-C-ACTGTAAGGTGCTGAGCCTTTGGATAGCC-CGCGAATGAT-CC-TAGTTGACAA-CTGAACGCGCTCGAACA-TGCCC-GCCCTCTGA--CTGCTGTCTG-GCACCTTTAGACACGCGTCGAC-CATATATT-AGCGCTGTCTGTGG-AGGT-TGTGTCTTGTTGCTCA-CT-CATTATCTGT-AACTGGCTCC-CTC-CCAT-TGGCGTCTTTACACCAACCGCTAGGTTACAGTGCA-TCTAGCGCCTATTATCAGGGCGT-TTGCAGCGGCGCGGTGGCTATGT-GTTAGACATATC-CTTACACTGTATGCTAG-AGCAAGCCAC-TCTGAATGGGTTGC-CGATGAATGA-TCTTGATC-GAGCTCGCA-AC---TACATGGAGTCCGAAGTGAACCTACGGATGATCGTATTCCAACACGAGGATC-TATACGTATAGG-A-GGCG-TAATCCACAATTTAGTAACTCTTGACGC---GGATGAAAAT-GTCGTTACACCTTCCAGAGGCTCGG-GTATATATATGACCT--TGTGATTGAGGACGATCTAGAATAA-CT-GT-G-CT-AAAGTACAGTAGTTTCTATGT-GGTAGGTGGAGAATACAGAGTAG-ATGATTC-GTGGGCCACA-C--T-ACTTTCAT-TAGAGCAGAGA-C-GTGAGTGAGTTTTACACTAGCCAGATGGACCG-GTGA-AGTCTAACAGCCACCGCTT-GTGAGGTCGTTTCCCAGTC-ACCCTACTACAGGCAAAAACTCAGTGT-CC-GTGA-GTGCGTTAGTGATATTCCCTAACGGTTAGGTAACT-CATGAATTCA-AT-TAAGCGTGTCC-CGGT-CACGCCCCCATGGGGGCCTTCTTGGGAGG--AGCATCTTAT--AT-GCTCACGTGGTT-GATAGG-A-T-AATACACTTTTAGTCAGTCCATCAATAAC-AAAGGAAC---CAGGTGGTCGCAGATA-TCCCGCTGATATAGCACTGTGTAAACTCAGGTGATA-CTAAGC--GCTCTAAT-ACG-CTTAATGGCAATGCCCAGTTC--ACGACTAGCTTATGAGGCCCAGCTATGGACTGCGGC-GGCATGTCGGC-GATGGTTGCCCTCGCCCTAAATTATGTACGA-T-ACCGCCT-CTTGTTCT-CCGCCCATAGGGT-C--AGCAGGCGATAGACTCCCAGAAATTTCCTCGTCGT-CCGAATAAGACTAACACGACTA-TT-CCTCTAC-GT-G-AA-CTTATCA-CAAATG-GCT-TACC-TAGGTGGTGGCAGATCACTTTCCGGTG-TATTACGAATTGACGCATACCGAC-A-CGC-GCTTGTTGGATAATCGACTCTAACCTCCTCTCTGGCACATGT-GCTGGATTACCTC-TATTTT-TCTCGCTTAG--GGAACG-T-CCTCTGTCGCGTGAG-GTACGTTTCACGGGAG-CGGCTTGTTCATGCCACGTCCATTATCGA-AGTG-C-GTAAGG-A-GAGCCCTA--GACTCTACACGGAAA-TC-AAC-GTAGAAGGCTC-A-CT`,
	}
	return utils.Validate(r, tps, fps)
}


func AWSSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "aws-secret-key",
		Description: "Identified a potential AWS Secret Access Key. Leaking these keys can lead to unauthorized access to your AWS account, data breaches, and significant security risks.",
		Regex:       regexp.MustCompile(`\b([A-Z0-9+/]{40})\b`),
		Entropy:     4.5, // High confidence due to specific format
		Keywords: []string{
			// Underscore versions
			"aws_secret_access_key",
			"aws_secret",
			"secret_access_key",
			"access_key_secret",
			// No separator versions
			"awssecret",
			"awssecretkey",
			"SecretAccessKey", // Used in AWS credentials files (case-sensitive usually, but keyword matching is case-insensitive)
			// Hyphen versions
			"aws-secret-access-key",
			"aws-secret",
			"secret-access-key",
			"access-key-secret",
		},
		Allowlists: []*config.Allowlist{
			{
				StopWords: []string{
					"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // Common example key
				},
				Description: "Allow common AWS example secret key",
			},
			// Add more specific allowlists if needed based on actual FPs
		},
	}

	// validate
	tps := []string{
		// Basic match with underscore keyword
		utils.GenerateSampleSecret("aws_secret", secrets.NewSecret(`[A-Z0-9+/]{40}`)),
		// Specific valid-looking key (not the common example) with underscore
		`secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY"`, // gitleaks:allow
		// Another random-like key with no separator keyword
		`awssecret=TY07k/hSnaU4KV/0Dyh6SjF/QoaR73lfWeLIL7bO`, // gitleaks:allow
		// Embedded in JSON/YAML with standard AWS keyword
		`"SecretAccessKey": "Vphb0b+C/1mHnUSWe/4QHsepLEXhY1EEGAj/6aCS"`, // gitleaks:allow
		// Key alone surrounded by spaces/boundaries
		` wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY `, // gitleaks:allow

		// --- Examples with hyphens ---
		// Basic match with hyphen keyword
		utils.GenerateSampleSecret("aws-secret", secrets.NewSecret(`[A-Z0-9+/]{40}`)),
		// Specific valid-looking key with hyphen
		`secret-access-key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY"`, // gitleaks:allow
		// Another random-like key with hyphen keyword
		`aws-secret-access-key: TY07k/hSnaU4KV/0Dyh6SjF/QoaR73lfWeLIL7bO`, // gitleaks:allow
	}
	fps := []string{
		// Too short
		`aws_secret_key=` + secrets.NewSecret(`[A-Z0-9+/]{39}`),
		// Too long
		`aws-secret-key=` + secrets.NewSecret(`[A-Z0-9+/]{41}`), // Added hyphen variation
		// Invalid characters (lowercase 'w', hyphen)
		`aws_secret_access_key="wjalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
		`aws-secret-access-key="wJalrXUtnFEMI-K7MDENG/bPxRfiCYEXAMPLEKEY"`, // Added hyphen variation
		// Example key (should be caught by rule allowlist)
		`AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, // gitleaks:allow
		// Low entropy (should be caught by global allowlist)
		`aws_secret_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, // gitleaks:allow
		// Access Key ID (should be caught by the *other* AWS rule)
		`AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"`, // gitleaks:allow
		// Part of a longer string (should fail boundary checks)
		`somestringwJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEYanotherstring`,
		`wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEYanotherstring`,
		`somestringwJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY`,
		// Common Base64 string that might otherwise match length but not format/entropy usually
		`Zm9vYmFyYmF6Zm9vYmFyYmF6Zm9vYmFyYmF6`, // "foobarbazfoobarbazfoobarbazfoobarbaz"
	}

	return utils.Validate(r, tps, fps)
}
