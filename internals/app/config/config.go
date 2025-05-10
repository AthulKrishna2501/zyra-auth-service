package config

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/spf13/viper"
)

type Config struct {
	PORT           string `mapstructure:"PORT" json:"PORT"`
	DB_URL         string `mapstructure:"DB_URL" json:"DB_URL"`
	JWT_SECRET_KEY string `mapstructure:"JWT_SECRET_KEY" json:"JWT_SECRET_KEY"`
	EMAIL_ADDRES   string `mapstructure:"ADMIN_EMAIL" json:"ADMIN_EMAIL"`
	EMAIL_PASSWORD string `mapstructure:"ADMIN_PASSWORD" json:"ADMIN_PASSWORD"`
	RABBITMQ_URL   string `mapstructure:"RABBITMQ_URL" json:"RABBITMQ_URL"`
	OAUTH_ID       string `mapstructure:"OAUTH_ID" json:"OAUTH_ID"`
	OAUTH_SECRET   string `mapstructure:"OAUTH_SECRET" json:"OAUTH_SECRET"`
	CALLBACK_URL   string `mapstructure:"CALLBACK_URL"`
	SECRET_NAME    string `mapstructure:"SECRET_NAME" json:"SECRET_NAME"`
}

func LoadConfig() (cfg Config, err error) {
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	paths := []string{".env", "../.env", "/app/.env"}
	loaded := false

	for _, path := range paths {
		viper.SetConfigFile(path)
		if err := viper.ReadInConfig(); err == nil {
			log.Printf("Loaded configuration from %s", path)
			loaded = true
			break
		} else {
			log.Printf("Failed to load %s: %v", path, err)
		}
	}

	if loaded {
		err = viper.Unmarshal(&cfg)
		if err != nil {
			log.Printf("Failed to unmarshal config from env: %v", err)
			return cfg, err
		}
		log.Printf("Config loaded from env: %+v", cfg)
		return cfg, nil
	}

	log.Println("Falling back to AWS Secrets Manager for configuration")
	secretName := os.Getenv("SECRET_NAME")
	if secretName == "" {
		secretName = "zyra/prod/auth-service/env"
	}
	log.Printf("Using secret name: %s", secretName)

	err = loadFromSecretsManager(&cfg, secretName)
	if err != nil {
		log.Printf("Failed to load config from Secrets Manager: %v", err)
		return cfg, err
	}
	log.Printf("Config loaded from Secrets Manager: %+v", cfg)
	return cfg, nil
}

func loadFromSecretsManager(cfg *Config, secretName string) error {
	ctx := context.TODO()

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Printf("Failed to load AWS config: %v", err)
		return err
	}

	client := secretsmanager.NewFromConfig(awsCfg)

	result, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		log.Printf("Failed to get secret value: %v", err)
		return err
	}

	secretString := *result.SecretString
	log.Printf("Retrieved secret: %s", secretString)
	return json.Unmarshal([]byte(secretString), cfg)
}
