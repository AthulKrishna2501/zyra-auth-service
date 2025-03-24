package config

import (
	"log"
	"path/filepath"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	PORT           string `mapstructure:"PORT"`
	DB_URL         string `mapstructure:"DB_URL"`
	JWT_SECRET_KEY string `mapstructure:"JWT_SECRET_KEY"`
	EMAIL_ADDRES   string `mapstructure:"EMAIL_ADDRES"`
	EMAIL_PASSWORD string `mapstructure:"EMAIL_PASSWORD"`
	RABBITMQ_URL   string `mapstructure:"RABBITMQ_URL"`
	OAUTH_ID      string `mapstructure:"OAUTH_ID  "`
	OAUTH_SECRET  string `mapstructure:"OAUTH_SECRET"`
}

func LoadConfig() (cfg Config, err error) {
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	viper.SetConfigFile(".env")
	if err := viper.ReadInConfig(); err == nil {
		log.Println("Loaded .env from the current directory")
	} else {
		log.Println("Could not load .env from current directory, trying parent...")

		viper.SetConfigFile("../.env")
		if err := viper.ReadInConfig(); err == nil {
			log.Println("Loaded .env from parent directory")
		} else {
			log.Println("Could not load .env from parent directory, trying absolute path...")

			viper.SetConfigFile("/app/.env")
			if err := viper.ReadInConfig(); err == nil {
				log.Println("Loaded .env from absolute path (/app/.env)")
			} else {
				log.Fatalf("Error loading .env file: %v", err)
			}
		}
	}

	err = viper.Unmarshal(&cfg)
	return
}

func LoadEnv() {
	rootDir, err := filepath.Abs("../")
	if err != nil {
		log.Fatal("Error getting root directory:", err)
	}

	envPath := filepath.Join(rootDir, ".env")
	err = godotenv.Load(envPath)
	if err != nil {
		log.Fatal("Error loading .env file from", envPath)
	}

}
