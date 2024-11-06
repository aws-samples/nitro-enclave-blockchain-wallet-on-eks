package pod

import (
	"bytes"
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	log "github.com/sirupsen/logrus"
	"os"
)

func GetAWSWebIdentityCredentials(config *aws.Config, sessionName string) (*types.Credentials, error) {
	if config == nil {
		return &types.Credentials{}, errors.New("error happened validating config - value cannot be nil")
	}
	stsClient := sts.NewFromConfig(*config)

	webIdentityTokenFileLocation := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	if len(webIdentityTokenFileLocation) == 0 {
		return &types.Credentials{}, errors.New("error happened looking up AWS_WEB_IDENTITY_TOKEN_FILE environment variable - value cannot be nil")
	}

	awsRoleArn := os.Getenv("AWS_ROLE_ARN")
	if len(awsRoleArn) == 0 {
		return &types.Credentials{}, errors.New("error happened looking up AWS_ROLE_ARN environment variable - value cannot be empty")
	}

	log.Debugf("loading webIdentityTokenFile from %s", webIdentityTokenFileLocation)
	webIdentityTokenFile, err := os.ReadFile(webIdentityTokenFileLocation) // #nosec G304
	if err != nil {
		return &types.Credentials{}, err
	}

	roleSessionName := sessionName
	webIdentityTokenStr := bytes.NewBuffer(webIdentityTokenFile).String()
	durationSeconds := int32(900)

	webIdentityToken, err := stsClient.AssumeRoleWithWebIdentity(context.TODO(), &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &awsRoleArn,
		RoleSessionName:  &roleSessionName,
		WebIdentityToken: &webIdentityTokenStr,
		DurationSeconds:  &durationSeconds,
	})
	if err != nil {
		return &types.Credentials{}, err
	}

	return webIdentityToken.Credentials, nil
}
