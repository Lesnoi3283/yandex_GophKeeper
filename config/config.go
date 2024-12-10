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
	DefaultServerAddress       = "localhost:8080"
	DefaultGRPCAddress         = "localhost:50051"
	DefaultBaseURL             = "http://localhost:8080"
	DefaultLogLevel            = "info"
	DefaultDBConnectionString  = ""
	DefaultJWTSecretKey        = "superSecret"
	DefaultJWTTimeoutHours     = 5
	DefaultMaxBinDataChunkSize = 16
)

type confFileData struct {
	ServerAddress       string `json:"server_address"`
	GRPCAddress         string `json:"grpc_address"`
	BaseURL             string `json:"base_url"`
	DatabaseDsn         string `json:"database_dsn"`
	LogLevel            string `json:"log_level"`
	JWTSecretKey        string `json:"jwt_secret_key"`
	JWTTimeoutHours     int    `json:"jwt_timeout_hours"`
	HashiCorpAddress    string `json:"hashi_corp_address"`
	DebugMode           bool   `json:"debug_mode"`
	MaxBinDataChunkSize int    `json:"max_bin_data_chunk_size"`
}

// Config is a struct with configuration params.
type Config struct {
	ServerAddress   string
	GRPCAddress     string
	DBConnString    string
	LogLevel        string
	JWTSecretKey    string
	JWTTimeoutHours int
	ConfigFileName  string
	// HashiCorpVaultToken have to bi read from environment values only!
	HashiCorpToken   string
	HashiCorpAddress string
	// DebugMode will runs server without TLS.
	DebugMode bool
	// MaxBinDataChunkSize limits max size of bin data chunk. Value should be in bytes.
	MaxBinDataChunkSize int
}

// Configure reads configuration params from command line args, environmental variables and default constants.
func (c *Config) Configure() (err error) {
	// Get flag values
	flag.StringVar(&(c.ServerAddress), "a", DefaultServerAddress, "Address where server will work. Example: \"localhost:8080\".")
	flag.StringVar(&(c.GRPCAddress), "g", DefaultGRPCAddress, "Address where gRPC will work. Example: \"localhost:50051\".")
	flag.StringVar(&(c.LogLevel), "l", DefaultLogLevel, "Log level.")
	flag.StringVar(&(c.DBConnString), "d", DefaultDBConnectionString, "Database connection string.")
	flag.StringVar(&(c.JWTSecretKey), "s", DefaultJWTSecretKey, "JWT secret key.")
	flag.IntVar(&(c.JWTTimeoutHours), "j", DefaultJWTTimeoutHours, "JWT timeout hours.")
	flag.StringVar(&(c.ConfigFileName), "c", "", "Config file name.")
	flag.StringVar(&(c.HashiCorpAddress), "h", "", "hashi_corp_vault address.")
	flag.BoolVar(&(c.DebugMode), "u", false, "unsafe - Debug mode, no TLS.")
	flag.IntVar(&(c.MaxBinDataChunkSize), "m", DefaultMaxBinDataChunkSize, "Max bin data chunk size.")
	flag.Parse()

	// Get env values
	envServerAddress, foundServerAddress := os.LookupEnv("SERVER_ADDRESS")
	envGRPCAddress, foundGRPCAddress := os.LookupEnv("GRPC_ADDRESS")
	envLogLevel, foundLogLevel := os.LookupEnv("LOG_LEVEL")
	envDBConnString, foundDBConnString := os.LookupEnv("DATABASE_DSN")
	envJWTSecretKey, foundJWTSecretKey := os.LookupEnv("JWT_SECRET_KEY")
	envJWTTimeoutHours, foundJWTTimeoutHours := os.LookupEnv("JWT_TIMEOUT_HOURS")
	envConfigFile, foundConfigFile := os.LookupEnv("CONFIG")
	envHashiCorpToken, foundHashiCorpToken := os.LookupEnv("HASHI_CORP_TOKEN")
	envHashiCorpAddress, foundHashiCorpAddress := os.LookupEnv("HASHI_CORP_ADDRESS")
	_, foundDebugMode := os.LookupEnv("DEBUG_MODE")
	envMaxBinDataChunkSize, foundMaxBinDataChunkSize := os.LookupEnv("MAX_BIN_DATA_CHUNK_SIZE")

	// Set values from environment if not already set by flags
	if c.ServerAddress == DefaultServerAddress && foundServerAddress {
		c.ServerAddress = envServerAddress
	}
	if c.GRPCAddress == DefaultGRPCAddress && foundGRPCAddress {
		c.GRPCAddress = envGRPCAddress
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
	if foundHashiCorpToken {
		c.HashiCorpToken = envHashiCorpToken
	}
	if foundHashiCorpAddress {
		c.HashiCorpAddress = envHashiCorpAddress
	}
	if foundDebugMode {
		c.DebugMode = true
	}
	if foundMaxBinDataChunkSize {
		c.MaxBinDataChunkSize, err = strconv.Atoi(envMaxBinDataChunkSize)
		if err != nil {
			return fmt.Errorf("cant parse MaxBinDataChunkSize, err: %v", err)
		}
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
		if c.HashiCorpAddress == "" {
			c.HashiCorpAddress = confData.HashiCorpAddress
		}
		if c.DebugMode == false {
			c.DebugMode = confData.DebugMode
		}
		if c.MaxBinDataChunkSize == DefaultMaxBinDataChunkSize && confData.MaxBinDataChunkSize != 0 {
			c.MaxBinDataChunkSize = confData.MaxBinDataChunkSize
		}
	}

	return nil
}
