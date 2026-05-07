package spec

var (
	ValidKeyUsageNames     = validKeyUsageNames
	ValidKeyUsages         = validKeyUsages
	InitLabelsSpec         = (*LabelsSpec).init
	InitLabelRequirement   = (*LabelRequirement).init
	InitLabelValidator     = (*LabelValidator).init
	ValidateLabelValidator = (*LabelValidator).validate
)
