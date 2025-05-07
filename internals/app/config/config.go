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
	PORT           string `mapstructure:"PORT"`
	DB_URL         string `mapstructure:"DB_URL"`
	JWT_SECRET_KEY string `mapstructure:"JWT_SECRET_KEY"`
	EMAIL_ADDRES   string `mapstructure:"ADMIN_EMAIL"`
	EMAIL_PASSWORD string `mapstructure:"ADMIN_PASSWORD"`
	RABBITMQ_URL   string `mapstructure:"RABBITMQ_URL"`
	OAUTH_ID       string `mapstructure:"OAUTH_ID  "`
	OAUTH_SECRET   string `mapstructure:"OAUTH_SECRET"`
	SECRET_NAME    string `mapstructure:"SECRET_NAME"`
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
		}
	}

	if loaded {
		err = viper.Unmarshal(&cfg)
		return cfg, err
	}

	log.Println("Falling back to AWS Secrets Manager for configuration")
	secretName := os.Getenv("SECRET_NAME")
	if secretName == "" {
		secretName = "zyra/prod/auth-service/env"
	}

	err = loadFromSecretsManager(&cfg, secretName)
	return cfg, err
}

func loadFromSecretsManager(cfg *Config, secretName string) error {
	ctx := context.TODO()

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	client := secretsmanager.NewFromConfig(awsCfg)

	result, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(*result.SecretString), cfg)
}
