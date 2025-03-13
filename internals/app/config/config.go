package config

import (
	"log"

	"github.com/spf13/viper"
)

type Config struct {
	PORT           string `mapstructure:"PORT"`
	DB_URL         string `mapstructure:"DB_URL"`
	JWT_SECRET_KEY string `mapstructure:"JWT_SECRET_KEY"`
	EMAIL_ADDRES   string `mapstructure:"EMAIL_ADDRES"`
	EMAIL_PASSWORD string `mapstructure:"EMAIL_PASSWORD"`
}

func LoadConfig() (cfg Config, err error) {
	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.SetConfigFile("../.env")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading .env file: %v", err)
	}

	viper.AutomaticEnv()

	err = viper.Unmarshal(&cfg)

	return
}
