/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	signerTypes "aws/ethereum-signer/internal/types"
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
	"net/url"
	"os"
)

var version = "undefined"

func HandleRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: 500}, nil
	}
	log.Debugf("starting ethereum key handler lambda (%s)", version)
	log.Debugf("event:\n%s", requestJSON)

	operation := ""

	// todo finish refactoring - get rid of double switch
	switch {
	case request.HTTPMethod == "POST" && request.Path == "/key":
		operation = "ethKeyGenerator"

	//	change how handler is called -> pass key_id as param
	case request.HTTPMethod == "POST" && request.Resource == "/key/{key_id}/tx_signature":
		operation = "ethTxSignature"

	case request.HTTPMethod == "POST" && request.Resource == "/key/{key_id}/userop_signature":
		operation = "ethUserOpSignature"
	}

	// environment variable required for generate key, sign tx and sign user op
	nitroInstancePrivateDNS := os.Getenv("NITRO_INSTANCE_PRIVATE_DNS")
	validate = validator.New()

	switch operation {
	case "ethKeyGenerator":
		var keyGenerationRequest signerTypes.PlainKey
		err = json.Unmarshal([]byte(request.Body), &keyGenerationRequest)
		if err != nil {
			return events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: 500}, nil
		}

		keyGenerationRequestJSON, _ := json.Marshal(keyGenerationRequest)
		log.Debugf("key generation request: %s", keyGenerationRequestJSON)

		// trigger struct validation to ensure that the external key conforms with the required length
		err = validate.Struct(keyGenerationRequest)
		if err != nil {
			validationErrors := err.(validator.ValidationErrors)
			return events.APIGatewayProxyResponse{Body: validationErrors.Error(), StatusCode: 400}, nil
		}

		enclaveResult, err := handleGenerateKeyRequest(nitroInstancePrivateDNS, keyGenerationRequest)
		if err != nil {
			return events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: 500}, nil
		}

		enclaveResultJSON, err := json.Marshal(enclaveResult)
		if err != nil {
			return events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: 500}, nil
		}

		return events.APIGatewayProxyResponse{Body: string(enclaveResultJSON), StatusCode: 200}, nil

	//	enclave determines tx or user op based on passed parameters so no need to handle requests differently
	case "ethTxSignature", "ethUserOpSignature":

		keyIDParam, found := request.PathParameters["key_id"]
		if found {
			keyIDParam, err = url.QueryUnescape(keyIDParam)
			if err != nil {
				return events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: 400}, nil
			}
			if !isValidUUID(keyIDParam) {
				return events.APIGatewayProxyResponse{Body: "invalid keyID submitted", StatusCode: 400}, nil
			}
		}

		var signingRequestPayload signerTypes.UserSigningRequest

		err = json.Unmarshal([]byte(request.Body), &signingRequestPayload)
		if err != nil {
			return events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: 400}, nil
		}

		err := validate.Struct(signingRequestPayload)
		if err != nil {
			validationErrors := err.(validator.ValidationErrors)
			return events.APIGatewayProxyResponse{Body: validationErrors.Error(), StatusCode: 400}, nil
		}

		signedTX, err := handleSigningRequest(nitroInstancePrivateDNS, signingRequestPayload)
		if err != nil {
			return events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: 500}, nil
		}

		//return signedTX, nil
		signedTXJSON, err := json.Marshal(signedTX)
		if err != nil {
			return events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: 500}, nil
		}

		return events.APIGatewayProxyResponse{Body: string(signedTXJSON), StatusCode: 200}, nil

	default:
		return events.APIGatewayProxyResponse{Body: "operation not supported", StatusCode: 400}, nil

	}
}

func main() {

	logLevel, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		log.Fatalf("LOG_LEVEL value (%s) could not be parsed: %s", os.Getenv("LOG_LEVEL"), err)
	}

	log.SetLevel(logLevel)

	nitroInstancePrivateDNS := os.Getenv("NITRO_INSTANCE_PRIVATE_DNS")
	secretTable := os.Getenv("SECRETS_TABLE")
	keyARN := os.Getenv("KEY_ARN")

	if nitroInstancePrivateDNS == "" || secretTable == "" || keyARN == "" {
		panic("NITRO_INSTANCE_PRIVATE_DNS, SECRETS_TABLE or KEY_ARN cannot be empty")
	}

	lambda.Start(HandleRequest)
}
