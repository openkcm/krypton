package spec

var (
	ValidKeyUsageNames     = validKeyUsageNames
	ValidKeyUsages         = validKeyUsages
	InitLabelSpecs         = (*LabelSpecs).init
	InitLabelRequirement   = (*LabelRequirement).init
	InitLabelValidator     = (*LabelValidator).init
	ValidateLabelValidator = (*LabelValidator).validate
)
