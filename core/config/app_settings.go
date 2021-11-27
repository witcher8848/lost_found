package config

import (
	"lost_found/core/constants"
	"os"
)

type AppSettings struct {
	AppType   constants.AppType
	AppID     string
	AppSecret string

	VerificationToken string
	EncryptKey        string
}

func GetISVAppSettingsByEnv() *AppSettings {
	appID, appSecret, verificationToken, encryptKey := getAppSettingsByEnv()
	return NewISVAppSettings(appID, appSecret, verificationToken, encryptKey)
}

func GetInternalAppSettingsByEnv() *AppSettings {
	appID, appSecret, verificationToken, encryptKey := getAppSettingsByEnv()
	return NewInternalAppSettings(appID, appSecret, verificationToken, encryptKey)
}

func NewISVAppSettings(appID, appSecret, verificationToken, encryptKey string) *AppSettings {
	return newAppSettings(constants.AppTypeISV, appID, appSecret, verificationToken, encryptKey)
}

func NewInternalAppSettings(appID, appSecret, verificationToken, encryptKey string) *AppSettings {
	return newAppSettings(constants.AppTypeInternal, appID, appSecret, verificationToken, encryptKey)
}

func newAppSettings(appType constants.AppType, appID, appSecret, verificationToken, encryptKey string) *AppSettings {
	if appID == "" || appSecret == "" {
		panic("appID or appSecret is empty")
	}
	return &AppSettings{
		AppType:           appType,
		AppID:             appID,
		AppSecret:         appSecret,
		VerificationToken: verificationToken,
		EncryptKey:        encryptKey,
	}
}

func getAppSettingsByEnv() (string, string, string, string) {
	//修改地方1
	os.Setenv("APP_ID","cli_a00d67c8e5f8500c")
	os.Setenv("APP_SECRET","ikI0Ry3N4b2yItta0uU23eKjJw0X5Lf0")

	appID, appSecret, verificationToken, encryptKey := os.Getenv("APP_ID"), os.Getenv("APP_SECRET"),
		os.Getenv("VERIFICATION_TOKEN"), os.Getenv("ENCRYPT_KEY")
	if appID == "" {
		panic("environment variables not exist `APP_ID`")
	}
	if appSecret == "" {
		panic("environment variables not exist `APP_SECRET`")
	}
	return appID, appSecret, verificationToken, encryptKey
}
