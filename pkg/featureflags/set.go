package featureflags

var (
	// EntEnabled enables experimental ent-based engine for the database storages.
	// https://entgo.io/
	EntEnabled = NewFlag("ent_enabled")

	// ExpandEnv can enable or disable env expansion in the config which can be useful in environments where, e.g.,
	// $ sign is a part of the password for LDAP user.
	ExpandEnv = NewFlag("expand_env")

	// ForceConfigValidation can enable experimental JSON schema based config validation.
	ForceConfigValidation = NewFlag("force_config_validation")
)
