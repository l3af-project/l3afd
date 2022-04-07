// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/csv"
	"net/url"
	"strings"
	"time"

	"github.com/robfig/config"
	"github.com/rs/zerolog/log"
)

const (
	cfgFatalMsg    = "Could not read %s value %q from group %q in config file"
	cfgOptionalMsg = "Using default value %v after failure to read group:%s; field:%s"
)

//Config Shortcuts--------------------------------------------------------------
// Note: For all the LoadXXX functions, we now have an equivalent LoadOptionalXXX variant.
// The LoadOptionalXXX variant will accept a default value as a parameter and if it fails to
// read in a value from the cfg, will return the default value as opposed to terminating odnd.
// For any new parameters that are not essential and/or have reasonable defaults - it will be
// a good idea to use the LoadOptionalXXX function.

// LoadConfigString gets the value (as a string) for a field belonging to a group.
// If the group and field are present - it returns the value
// If the group or field are absent - it aborts the process
// Note: Values that are encrypted are decrypted using a global key
func LoadConfigString(confReader *config.Config, group, field string) string {
	return LoadConfigStringEncKey(confReader, group, field)
}

// LoadOptionalConfigString gets the value (as a string) for a field belonging to a group.
// If the group and field are present - it returns the value
// If the group or field are absent - it returns the supplied default value
// Note: Values that are encrypted are decrypted using a global key
func LoadOptionalConfigString(confReader *config.Config, group, field, defaultValue string) string {
	return LoadOptionalConfigStringEncKey(confReader, group, field, defaultValue)
}

// LoadOptionalConfigStringEncKey is similar to LoadOptionalConfigString, except that it accepts an optional decryption key.
func LoadOptionalConfigStringEncKey(confReader *config.Config, group, field, defaultValue string) string {
	val, err := loadConfigStringEncKey(confReader, group, field)
	if err != nil {
		log.Info().Err(err).Msgf(cfgOptionalMsg, defaultValue, group, field)
		return defaultValue
	}
	return val
}

// LoadConfigStringEncKey is similar to LoadConfigString, except that it accepts an optional decryption key.
func LoadConfigStringEncKey(confReader *config.Config, group, field string) string {
	val, err := loadConfigStringEncKey(confReader, group, field)
	if err != nil {
		log.Fatal().Err(err).Msgf(cfgFatalMsg, "text", field, group)
	}
	return val
}

// loadConfigStringEncKey attempts to read the value for a given group and field in a config object.
// If the value is absent - an error is returned to the caller, who can then abort execution or return a default.
// If the value is present - it is returned to the caller, and optionally decrypted if the value starts with `ENC:`
// Note: Decryption is done with the supplied key. If nil - a global key is used for decryption.
func loadConfigStringEncKey(confReader *config.Config, group, field string) (string, error) {
	//Read value from config reader
	value, err := confReader.String(group, field)
	if err != nil {
		return "", err
	}
	return value, nil
}

func LoadConfigBool(confReader *config.Config, group, field string) bool {
	value, err := confReader.Bool(group, field)
	if err != nil {
		log.Fatal().Err(err).Msgf(cfgFatalMsg, "logical", field, group)
	}
	return value
}

func LoadOptionalConfigBool(confReader *config.Config, group, field string, defaultValue bool) bool {
	value, err := confReader.Bool(group, field)
	if err != nil {
		log.Info().Err(err).Msgf(cfgOptionalMsg, defaultValue, group, field)
		return defaultValue
	}
	return value
}

func LoadConfigInt(confReader *config.Config, group, field string) int {
	value, err := confReader.Int(group, field)
	if err != nil {
		log.Fatal().Err(err).Msgf(cfgFatalMsg, "integer", field, group)
	}
	return value
}

func LoadOptionalConfigInt(confReader *config.Config, group, field string, defaultValue int) int {
	value, err := confReader.Int(group, field)
	if err != nil {
		log.Info().Err(err).Msgf(cfgOptionalMsg, defaultValue, group, field)
		return defaultValue
	}
	return value
}

func LoadConfigFloat(confReader *config.Config, group, field string) float64 {
	value, err := confReader.Float(group, field)
	if err != nil {
		log.Fatal().Err(err).Msgf(cfgFatalMsg, "decimal point", field, group)
	}
	return value
}

func LoadOptionalConfigFloat(confReader *config.Config, group, field string, defaultValue float64) float64 {
	value, err := confReader.Float(group, field)
	if err != nil {
		log.Info().Err(err).Msgf(cfgOptionalMsg, defaultValue, group, field)
		return defaultValue
	}
	return value
}

func LoadConfigDuration(confReader *config.Config, group, field string) time.Duration {
	value, err := time.ParseDuration(LoadConfigString(confReader, group, field))
	if err != nil {
		log.Fatal().Err(err).Msgf(cfgFatalMsg, "duration", field, group)
	}
	return value
}

func LoadOptionalConfigDuration(confReader *config.Config, group, field string, defaultValue time.Duration) time.Duration {
	stringValue := LoadOptionalConfigString(confReader, group, field, "")
	if len(stringValue) == 0 {
		return defaultValue
	}

	value, err := time.ParseDuration(stringValue)
	if err != nil {
		log.Info().Err(err).Msgf(cfgOptionalMsg, defaultValue, group, field)
		return defaultValue
	}
	return value
}

func LoadConfigURL(confReader *config.Config, group, field string) *url.URL {
	value, err := url.Parse(LoadConfigString(confReader, group, field))
	if err != nil {
		log.Fatal().Err(err).Msgf(cfgFatalMsg, "url", field, group)
	}
	return value
}

func LoadOptionalConfigURL(confReader *config.Config, group, field string, defaultValue *url.URL) *url.URL {
	stringValue := LoadOptionalConfigString(confReader, group, field, "")
	if len(stringValue) == 0 {
		return defaultValue
	}

	value, err := url.Parse(stringValue)
	if err != nil {
		log.Info().Err(err).Msgf(cfgOptionalMsg, defaultValue, group, field)
		return defaultValue
	}
	return value
}

// LoadConfigStringCSV splits a CSV config string value and returns the
// resulting slice of strings. An emptyDefault []string is returned if the config
// field is emptyDefault (as opposed to []string{""}, which strings.Split() would
// return).
func LoadConfigStringCSV(confReader *config.Config, group, field string) []string {
	CSVStr := strings.TrimSpace(LoadConfigString(confReader, group, field))
	if CSVStr == "" {
		return []string{}
	}
	vals, err := csv.NewReader(strings.NewReader(CSVStr)).Read()
	if err != nil {
		log.Fatal().Err(err).Msgf(cfgFatalMsg, "CSV string", field, group)
	}
	return vals
}

func LoadOptionalConfigStringCSV(confReader *config.Config, group, field string, defaultValue []string) []string {
	val, err := loadConfigStringEncKey(confReader, group, field)
	if err != nil {
		log.Info().Err(err).Msgf(cfgOptionalMsg, defaultValue, group, field)
		return defaultValue
	}
	CSVStr := strings.TrimSpace(val)
	if CSVStr == "" {
		return []string{}
	}
	vals, err := csv.NewReader(strings.NewReader(CSVStr)).Read()
	if err != nil {
		log.Fatal().Err(err).Msgf(cfgFatalMsg, "CSV string", field, group)
	}
	return vals
}
