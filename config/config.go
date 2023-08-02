package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	ojson "github.com/clarketm/json"
	"github.com/dexidp/dex/pkg/featureflags"
	"github.com/invopop/jsonschema"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/bcrypt"

	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/ent"
	"github.com/dexidp/dex/storage/etcd"
	"github.com/dexidp/dex/storage/kubernetes"
	"github.com/dexidp/dex/storage/memory"
	"github.com/dexidp/dex/storage/sql"
)

// Config is the config format for the main application.
type Config struct {
	Issuer    string    `json:"issuer" jsonschema:"required,minLength=1"`
	Storage   Storage   `json:"storage" jsonschema:"required"`
	Web       Web       `json:"web,omitempty"`
	Telemetry Telemetry `json:"telemetry,omitempty"`
	OAuth2    OAuth2    `json:"oauth2,omitempty"`
	GRPC      GRPC      `json:"grpc,omitempty"`
	Expiry    Expiry    `json:"expiry,omitempty"`

	// Logger carries options for controlling the logger.
	Logger Logger `json:"logger,omitempty"`

	// Frontend defines the configuration for Dex appearance.
	Frontend server.WebConfig `json:"frontend,omitempty"`

	// StaticConnectors are user defined connectors specified in the ConfigMap
	// Write operations, like updating a connector, will fail.
	StaticConnectors []Connector `json:"connectors,omitempty"`

	// StaticClients cause the server to use this list of clients rather than
	// querying the storage. Write operations, like creating a client, will fail.
	StaticClients []Client `json:"staticClients,omitempty"`

	// EnablePasswordDB specifies that server will maintain a list of passwords which can be used
	// to identify a user.
	EnablePasswordDB bool `json:"enablePasswordDB"`

	// StaticPasswords cause the server use this list of passwords rather than
	// querying the storage. Cannot be specified without enabling a passwords
	// database.
	StaticPasswords []Password `json:"staticPasswords,omitempty"`
}

func (c *Config) JSONSchema() ([]byte, error) {
	reflector := jsonschema.Reflector{
		Anonymous:                  true,
		DoNotReference:             true,
		RequiredFromJSONSchemaTags: true,  // all properties are optional by default
		AllowAdditionalProperties:  false, // unrecognized properties don't cause a parsing failures
	}
	if err := reflector.AddGoComments("github.com/dexidp/dex", "./"); err != nil {
		return nil, fmt.Errorf("cannot get schema comments: %v", err) // must never happen
	}

	rawSchema, err := reflector.Reflect(c).MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("cannot conmpose configuation schema from structures: %v", err) // must never happen
	}

	return rawSchema, nil
}

func (c *Config) ValidateWithSchema() (*gojsonschema.Result, error) {
	rawSchema, err := c.JSONSchema()
	if err != nil {
		return nil, err
	}

	v, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(rawSchema))
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal configuration schema: %v", err)
	}

	// Omit empty structs to prevent validation fails by marshalling config back with a forked json lib.
	data, err := ojson.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal config: %v\n", err)
	}

	res, err := v.Validate(gojsonschema.NewBytesLoader(data))
	if err != nil {
		return nil, fmt.Errorf("validating with a schema: %v\n", err)
	}

	return res, nil
}

// Validate the configuration
func (c *Config) Validate(logger log.Logger) error {
	validationRes, err := c.ValidateWithSchema()
	if featureflags.ForceConfigValidation.Enabled() && err != nil {
		return fmt.Errorf("cannot validate config with a schema: %v", err)
	}

	if !validationRes.Valid() {
		for _, err := range validationRes.Errors() {
			logger.Warnf("config validation: %s", err.String())
		}
		if featureflags.ForceConfigValidation.Enabled() {
			return fmt.Errorf("config is not valid")
		}
	}

	// Fast checks. Perform these first for a more responsive CLI.
	checks := []struct {
		bad    bool
		errMsg string
	}{
		// TODO(nabokihms): some of checks are duplicated by jsonschema, consider migrating to a single solution.
		{c.Issuer == "", "no issuer specified in config file"},
		{!c.EnablePasswordDB && len(c.StaticPasswords) != 0, "cannot specify static passwords without enabling password db"},
		{c.Storage.Config == nil, "no storage supplied in config file"},
		{c.Web.HTTP == "" && c.Web.HTTPS == "", "must supply a HTTP/HTTPS  address to listen on"},
		{c.Web.HTTPS != "" && c.Web.TLSCert == "", "no cert specified for HTTPS"},
		{c.Web.HTTPS != "" && c.Web.TLSKey == "", "no private key specified for HTTPS"},
		{c.GRPC.TLSCert != "" && c.GRPC.Addr == "", "no address specified for gRPC"},
		{c.GRPC.TLSKey != "" && c.GRPC.Addr == "", "no address specified for gRPC"},
		{(c.GRPC.TLSCert == "") != (c.GRPC.TLSKey == ""), "must specific both a gRPC TLS cert and key"},
		{c.GRPC.TLSCert == "" && c.GRPC.TLSClientCA != "", "cannot specify gRPC TLS client CA without a gRPC TLS cert"},
	}

	var checkErrors []string

	for _, check := range checks {
		if check.bad {
			checkErrors = append(checkErrors, check.errMsg)
		}
	}
	if len(checkErrors) > 0 {
		for _, s := range checkErrors {
			logger.Errorf("config validation: %s", s)
		}
		return fmt.Errorf("config is not valid")
	}

	return nil
}

// Overrides are config defaults from external sources, e.g., CLI flags.
type Overrides struct {
	WebHTTPAddr   string
	WebHTTPSAddr  string
	TelemetryAddr string
	GRPCAddr      string
}

// ApplyOverrides adds defaults to configuration.
func (c *Config) ApplyOverrides(o *Overrides) *Config {
	if o.WebHTTPAddr != "" {
		c.Web.HTTP = o.WebHTTPAddr
	}

	if o.WebHTTPSAddr != "" {
		c.Web.HTTPS = o.WebHTTPSAddr
	}

	if o.TelemetryAddr != "" {
		c.Telemetry.HTTP = o.TelemetryAddr
	}

	if o.GRPCAddr != "" {
		c.GRPC.Addr = o.GRPCAddr
	}

	if c.Frontend.Dir == "" {
		c.Frontend.Dir = os.Getenv("DEX_FRONTEND_DIR")
	}

	if len(c.OAuth2.ResponseTypes) == 0 {
		c.OAuth2.ResponseTypes = []string{"code"}
	}

	if len(c.OAuth2.GrantTypes) == 0 {
		c.OAuth2.GrantTypes = []string{
			"authorization_code",
			"implicit",
			"password",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		}
	}

	if c.Logger.Format == "" {
		c.Logger.Format = "text"
	}
	if c.Logger.Level == "" {
		c.Logger.Level = "info"
	}

	if c.Frontend.Issuer == "" {
		c.Frontend.Issuer = "dex"
	}
	if c.Frontend.Theme == "" {
		c.Frontend.Theme = "light"
	}

	return c
}

func (c *Config) Log(logger log.Logger) {
	logger.Infof("config issuer: %s", c.Issuer)

	if len(c.OAuth2.ResponseTypes) > 0 {
		logger.Infof("config response types accepted: %s", c.OAuth2.ResponseTypes)
	}
	if c.OAuth2.SkipApprovalScreen {
		logger.Infof("config skipping approval screen")
	}
	if c.OAuth2.PasswordConnector != "" {
		logger.Infof("config using password grant connector: %s", c.OAuth2.PasswordConnector)
	}

	if len(c.Web.AllowedOrigins) > 0 {
		logger.Infof("config allowed origins: %s", c.Web.AllowedOrigins)
	}

	if c.EnablePasswordDB {
		logger.Infof("config connector: local passwords enabled")
	}

	if c.Logger.Level != "" {
		logger.Infof("config using log level: %s", c.Logger.Level)
	}
	if c.Logger.Format != "" {
		logger.Infof("config using log format: %s", c.Logger.Format)
	}

	if c.Expiry.SigningKeys != "" {
		logger.Infof("config signing keys expire after: %v", c.Expiry.SigningKeys)
	}
	if c.Expiry.IDTokens != "" {
		logger.Infof("config id tokens valid for: %v", c.Expiry.IDTokens)
	}
	if c.Expiry.AuthRequests != "" {
		logger.Infof("config auth requests valid for: %v", c.Expiry.AuthRequests)
	}
	if c.Expiry.DeviceRequests != "" {
		logger.Infof("config device requests valid for: %v", c.Expiry.DeviceRequests)
	}
}

type Password struct {
	Email       string `json:"email" jsonschema:"required,minLength=1" jsonschema_extras:"format=email"`
	Hash        string `json:"hash,omitempty" jsonschema:"oneof_required=hash"`
	HashFromEnv string `json:"hashFromEnv,omitempty" jsonschema:"oneof_required=envhash"`
	Username    string `json:"username,omitempty"`
	UserID      string `json:"userID,omitempty"`
}

// ToStoragePassword converts an object to storage password type.
func ToStoragePassword(p Password) (storage.Password, error) {
	hash := p.Hash

	if len(hash) == 0 && len(p.HashFromEnv) > 0 {
		hash = os.Getenv(p.HashFromEnv)
	}
	if len(hash) == 0 {
		return storage.Password{}, fmt.Errorf("no password hash provided")
	}

	// If this value is a valid bcrypt, use it.
	_, bcryptErr := bcrypt.Cost([]byte(hash))
	if bcryptErr != nil {
		// For backwards compatibility try to base64 decode this value.
		hashBytes, err := base64.StdEncoding.DecodeString(hash)
		if err != nil {
			return storage.Password{}, fmt.Errorf("malformed bcrypt hash: %v", bcryptErr)
		}
		if _, err := bcrypt.Cost(hashBytes); err != nil {
			return storage.Password{}, fmt.Errorf("malformed bcrypt hash: %v", err)
		}

		hash = string(hashBytes)
	}

	return storage.Password{
		Email:    p.Email,
		Username: p.Username,
		UserID:   p.UserID,
		Hash:     []byte(hash),
	}, nil
}

// OAuth2 describes enabled OAuth2 extensions.
type OAuth2 struct {
	// GrantTypes defines the list of allowed grant types, defaults to all supported types.
	GrantTypes []string `json:"grantTypes,omitempty"`

	ResponseTypes []string `json:"responseTypes,omitempty"`

	// SkipApprovalScreen specifies that Dex doesn't need to prompt the user to approve client authorization. The
	// act of logging in implies authorization.
	SkipApprovalScreen bool `json:"skipApprovalScreen,omitempty"`

	// If specified, show the connector selection screen even if there's only one
	AlwaysShowLoginScreen bool `json:"alwaysShowLoginScreen,omitempty"`

	// PasswordConnector is the connector's name that can be used for password grant.
	PasswordConnector string `json:"passwordConnector,omitempty"`
}

// Web is the config format for the HTTP server.
type Web struct {
	HTTP           string   `json:"http,omitempty" jsonschema:"anyof_required=http" jsonschema_extras:"format=listen-address"`
	HTTPS          string   `json:"https,omitempty" jsonschema:"anyof_required=https" jsonschema_extras:"format=listen-address"`
	TLSCert        string   `json:"tlsCert,omitempty" jsonschema:"anyof_required=https"`
	TLSKey         string   `json:"tlsKey,omitempty" jsonschema:"anyof_required=https"`
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
}

// Telemetry is the config format for telemetry including the HTTP server config.
type Telemetry struct {
	HTTP string `json:"http,omitempty" jsonschema:"required" jsonschema_extras:"format=listen-address"`
	// EnableProfiling makes profiling endpoints available via web interface host:port/debug/pprof/
	EnableProfiling bool `json:"enableProfiling,omitempty"`
}

// GRPC is the config for the gRPC API.
type GRPC struct {
	// The port to listen on.
	Addr        string `json:"addr" jsonschema:"required" jsonschema_extras:"format=listen-address"`
	TLSCert     string `json:"tlsCert" jsonschema:"required"`
	TLSKey      string `json:"tlsKey" jsonschema:"required"`
	TLSClientCA string `json:"tlsClientCA,omitempty"`
	Reflection  bool   `json:"reflection,omitempty"`
}

// Storage holds app's storage configuration.
type Storage struct {
	Type   string        `json:"type" jsonschema:"required,minLength=1,enum=etcd,enum=kubernetes,enum=memory,enum=sqlite3,enum=postgres,enum=mysql"`
	Config StorageConfig `json:"config" jsonschema:"required"`
}

// StorageConfig is a configuration that can create a storage.
type StorageConfig interface {
	Open(logger log.Logger) (storage.Storage, error)
}

var (
	_ StorageConfig = (*etcd.Etcd)(nil)
	_ StorageConfig = (*kubernetes.Config)(nil)
	_ StorageConfig = (*memory.Config)(nil)
	_ StorageConfig = (*sql.SQLite3)(nil)
	_ StorageConfig = (*sql.Postgres)(nil)
	_ StorageConfig = (*sql.MySQL)(nil)
	_ StorageConfig = (*ent.SQLite3)(nil)
	_ StorageConfig = (*ent.Postgres)(nil)
	_ StorageConfig = (*ent.MySQL)(nil)
)

func getORMBasedSQLStorage(normal, entBased StorageConfig) func() StorageConfig {
	return func() StorageConfig {
		if featureflags.EntEnabled.Enabled() {
			return entBased
		}
		return normal
	}
}

var storages = map[string]func() StorageConfig{
	"etcd":       func() StorageConfig { return new(etcd.Etcd) },
	"kubernetes": func() StorageConfig { return new(kubernetes.Config) },
	"memory":     func() StorageConfig { return new(memory.Config) },
	"sqlite3":    getORMBasedSQLStorage(&sql.SQLite3{}, &ent.SQLite3{}),
	"postgres":   getORMBasedSQLStorage(&sql.Postgres{}, &ent.Postgres{}),
	"mysql":      getORMBasedSQLStorage(&sql.MySQL{}, &ent.MySQL{}),
}

// UnmarshalJSON allows Storage to implement the unmarshaler interface to
// dynamically determine the type of the storage config.
func (s *Storage) UnmarshalJSON(b []byte) error {
	var store struct {
		Type   string          `json:"type"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(b, &store); err != nil {
		return fmt.Errorf("parse storage: %v", err)
	}
	f, ok := storages[store.Type]
	if !ok {
		return fmt.Errorf("unknown storage type %q", store.Type)
	}

	storageConfig := f()
	if len(store.Config) != 0 {
		data := []byte(store.Config)
		if featureflags.ExpandEnv.Enabled() {
			// Caution, we're expanding in the raw JSON/YAML source. This may not be what the admin expects.
			data = []byte(os.ExpandEnv(string(store.Config)))
		}
		if err := json.Unmarshal(data, storageConfig); err != nil {
			return fmt.Errorf("parse storage config: %v", err)
		}
	}
	*s = Storage{
		Type:   store.Type,
		Config: storageConfig,
	}
	return nil
}

// Connector is a magical type that can unmarshal YAML dynamically. The
// Type field determines the connector type, which is then customized for Config.
type Connector struct {
	Type string `json:"type" jsonschema:"required,minLength=1"`
	Name string `json:"name" jsonschema:"required,minLength=1"`
	ID   string `json:"id"   jsonschema:"required,minLength=1"`

	Config server.ConnectorConfig `json:"config"`
}

// UnmarshalJSON allows Connector to implement the unmarshaler interface to
// dynamically determine the type of the connector config.
func (c *Connector) UnmarshalJSON(b []byte) error {
	var conn struct {
		Type string `json:"type"`
		Name string `json:"name"`
		ID   string `json:"id"`

		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(b, &conn); err != nil {
		return fmt.Errorf("parse connector: %v", err)
	}
	f, ok := server.ConnectorsConfig[conn.Type]
	if !ok {
		return fmt.Errorf("unknown connector type %q", conn.Type)
	}

	connConfig := f()
	if len(conn.Config) != 0 {
		data := []byte(conn.Config)
		if featureflags.ExpandEnv.Enabled() {
			// Caution, we're expanding in the raw JSON/YAML source. This may not be what the admin expects.
			data = []byte(os.ExpandEnv(string(conn.Config)))
		}
		if err := json.Unmarshal(data, connConfig); err != nil {
			return fmt.Errorf("parse connector config: %v", err)
		}
	}
	*c = Connector{
		Type:   conn.Type,
		Name:   conn.Name,
		ID:     conn.ID,
		Config: connConfig,
	}
	return nil
}

// ToStorageConnector converts an object to storage connector type.
func ToStorageConnector(c Connector) (storage.Connector, error) {
	data, err := json.Marshal(c.Config)
	if err != nil {
		return storage.Connector{}, fmt.Errorf("failed to marshal connector config: %v", err)
	}

	return storage.Connector{
		ID:     c.ID,
		Type:   c.Type,
		Name:   c.Name,
		Config: data,
	}, nil
}

// Client is the representation of storage.Client for configuration.
type Client struct {
	ID           string   `json:"id,omitempty"`
	IDEnv        string   `json:"idEnv,omitempty"`
	Secret       string   `json:"secret,omitempty"`
	SecretEnv    string   `json:"secretEnv,omitempty"`
	RedirectURIs []string `json:"redirectURIs,omitempty"`
	TrustedPeers []string `json:"trustedPeers,omitempty"`
	Public       bool     `json:"public"`
	Name         string   `json:"name" jsonschema:"required,minLength=1"`
	LogoURL      string   `json:"logoURL,omitempty"`
}

func ToStorageClient(client Client) (storage.Client, error) {
	if client.Name == "" {
		return storage.Client{}, fmt.Errorf("invalid config: Name field is required for a client")
	}
	if client.ID == "" && client.IDEnv == "" {
		return storage.Client{}, fmt.Errorf("invalid config: ID or IDEnv field is required for a client")
	}
	if client.IDEnv != "" {
		if client.ID != "" {
			return storage.Client{}, fmt.Errorf("invalid config: ID and IDEnv fields are exclusive for client %q", client.ID)
		}
		client.ID = os.Getenv(client.IDEnv)
	}
	if client.Secret == "" && client.SecretEnv == "" && !client.Public {
		return storage.Client{}, fmt.Errorf("invalid config: Secret or SecretEnv field is required for client %q", client.ID)
	}
	if client.SecretEnv != "" {
		if client.Secret != "" {
			return storage.Client{}, fmt.Errorf("invalid config: Secret and SecretEnv fields are exclusive for client %q", client.ID)
		}
		client.Secret = os.Getenv(client.SecretEnv)
	}

	return storage.Client{
		Name:         client.Name,
		ID:           client.ID,
		Secret:       client.Secret,
		RedirectURIs: client.RedirectURIs,
		TrustedPeers: client.TrustedPeers,
		LogoURL:      client.LogoURL,
		Public:       client.Public,
	}, nil
}

// Expiry holds configuration for the validity period of components.
type Expiry struct {
	// SigningKeys defines the duration of time after which the SigningKeys will be rotated.
	SigningKeys string `json:"signingKeys,omitempty" jsonschema_extras:"format=duration"`

	// IDTokens defines the duration of time for which the IdTokens will be valid.
	IDTokens string `json:"idTokens,omitempty" jsonschema_extras:"format=duration"`

	// AuthRequests defines the duration of time for which the AuthRequests will be valid.
	AuthRequests string `json:"authRequests,omitempty" jsonschema_extras:"format=duration"`

	// DeviceRequests defines the duration of time for which the DeviceRequests will be valid.
	DeviceRequests string `json:"deviceRequests,omitempty" jsonschema_extras:"format=duration"`

	// RefreshTokens defines refresh tokens expiry policy
	RefreshTokens RefreshToken `json:"refreshTokens,omitempty"`
}

// Logger holds configuration required to customize logging for dex.
type Logger struct {
	// Level sets logging level severity.
	Level string `json:"level" jsonschema:"enum=debug,enum=info,enum=error,default=info"`

	// Format specifies the format to be used for logging.
	Format string `json:"format" jsonschema:"enum=text,enum=json,default=text"`
}

type RefreshToken struct {
	DisableRotation   bool   `json:"disableRotation"`
	ReuseInterval     string `json:"reuseInterval,omitempty"  jsonschema_extras:"format=duration"`
	AbsoluteLifetime  string `json:"absoluteLifetime,omitempty"  jsonschema_extras:"format=duration"`
	ValidIfNotUsedFor string `json:"validIfNotUsedFor,omitempty"  jsonschema_extras:"format=duration"`
}
