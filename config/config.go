// Package config is a configuration package.
// It contains a Config struct and functions to read configuration params from env variables and command line args.
package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
)

// Default configuration params.
const (
	DefaultServerAddress      = "localhost:8080"
	DefaultGRPCAddress        = "localhost:50051"
	DefaultBaseURL            = "http://localhost:8080"
	DefaultLogLevel           = "info"
	DefaultDBConnectionString = ""
	DefaultJWTSecretKey       = "superSecret"
	DefaultJWTTimeoutHours    = 5
)

type confFileData struct {
	ServerAddress   string `json:"server_address"`
	GRPCAddress     string `json:"grpc_address"`
	BaseURL         string `json:"base_url"`
	DatabaseDsn     string `json:"database_dsn"`
	LogLevel        string `json:"log_level"`
	JWTSecretKey    string `json:"jwt_secret_key"`
	JWTTimeoutHours int    `json:"jwt_timeout_hours"`
}

// Config is a struct with configuration params.
type Config struct {
	ServerAddress   string
	GRPCAddress     string
	BaseURL         string
	DBConnString    string
	LogLevel        string
	JWTSecretKey    string
	JWTTimeoutHours int
	ConfigFileName  string
}

// Configure reads configuration params from command line args, environmental variables and default constants.
func (c *Config) Configure() error {
	// Get flag values
	flag.StringVar(&(c.ServerAddress), "a", DefaultServerAddress, "Address where server will work. Example: \"localhost:8080\".")
	flag.StringVar(&(c.GRPCAddress), "g", DefaultGRPCAddress, "Address where gRPC will work. Example: \"localhost:50051\".")
	flag.StringVar(&(c.BaseURL), "b", DefaultBaseURL, "Base URL for shortened links.")
	flag.StringVar(&(c.LogLevel), "l", DefaultLogLevel, "Log level.")
	flag.StringVar(&(c.DBConnString), "d", DefaultDBConnectionString, "Database connection string.")
	flag.StringVar(&(c.JWTSecretKey), "s", DefaultJWTSecretKey, "JWT secret key.")
	flag.IntVar(&(c.JWTTimeoutHours), "j", DefaultJWTTimeoutHours, "JWT timeout hours.")
	flag.StringVar(&(c.ConfigFileName), "c", "", "Config file name.")
	flag.Parse()

	// Get env values
	envServerAddress, foundServerAddress := os.LookupEnv("SERVER_ADDRESS")
	envGRPCAddress, foundGRPCAddress := os.LookupEnv("GRPC_ADDRESS")
	envBaseURL, foundBaseURL := os.LookupEnv("BASE_URL")
	envLogLevel, foundLogLevel := os.LookupEnv("LOG_LEVEL")
	envDBConnString, foundDBConnString := os.LookupEnv("DATABASE_DSN")
	envJWTSecretKey, foundJWTSecretKey := os.LookupEnv("JWT_SECRET_KEY")
	envJWTTimeoutHours, foundJWTTimeoutHours := os.LookupEnv("JWT_TIMEOUT_HOURS")
	envConfigFile, foundConfigFile := os.LookupEnv("CONFIG")

	// Set values from environment if not already set by flags
	if c.ServerAddress == DefaultServerAddress && foundServerAddress {
		c.ServerAddress = envServerAddress
	}
	if c.GRPCAddress == DefaultGRPCAddress && foundGRPCAddress {
		c.GRPCAddress = envGRPCAddress
	}
	if c.BaseURL == DefaultBaseURL && foundBaseURL {
		c.BaseURL = envBaseURL
	}
	if c.LogLevel == DefaultLogLevel && foundLogLevel {
		c.LogLevel = envLogLevel
	}
	if foundDBConnString {
		c.DBConnString = envDBConnString
	}
	if foundJWTSecretKey {
		c.JWTSecretKey = envJWTSecretKey
	}
	if foundJWTTimeoutHours {
		hours, err := strconv.Atoi(envJWTTimeoutHours)
		if err != nil {
			return fmt.Errorf("error parsing JWT_TIMEOUT_HOURS: %w", err)
		}
		c.JWTTimeoutHours = hours
	}

	// Read config file if specified
	if foundConfigFile {
		c.ConfigFileName = envConfigFile
		file, err := os.Open(c.ConfigFileName)
		if err != nil {
			return fmt.Errorf("could not open config file: %w", err)
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			return fmt.Errorf("could not read config file: %w", err)
		}

		confData := &confFileData{}
		err = json.Unmarshal(data, confData)
		if err != nil {
			return fmt.Errorf("could not parse config file: %w", err)
		}

		// Set values from config file if not already set
		if c.ServerAddress == DefaultServerAddress && confData.ServerAddress != "" {
			c.ServerAddress = confData.ServerAddress
		}
		if c.GRPCAddress == DefaultGRPCAddress && confData.GRPCAddress != "" {
			c.GRPCAddress = confData.GRPCAddress
		}
		if c.BaseURL == DefaultBaseURL && confData.BaseURL != "" {
			c.BaseURL = confData.BaseURL
		}
		if c.LogLevel == DefaultLogLevel && confData.LogLevel != "" {
			c.LogLevel = confData.LogLevel
		}
		if c.DBConnString == DefaultDBConnectionString && confData.DatabaseDsn != "" {
			c.DBConnString = confData.DatabaseDsn
		}
		if !foundJWTSecretKey && confData.JWTSecretKey != "" {
			c.JWTSecretKey = confData.JWTSecretKey
		}
		if c.JWTTimeoutHours == DefaultJWTTimeoutHours && confData.JWTTimeoutHours != 0 {
			c.JWTTimeoutHours = confData.JWTTimeoutHours
		}
	}

	return nil
}
