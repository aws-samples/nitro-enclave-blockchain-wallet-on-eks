package attestation

import (
	"errors"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

type AttestationProvider interface {
	GetAttestationDoc(nonce []byte, userData []byte, publicKey []byte) ([]byte, error)
}

type NitroAttestationProvider struct{}

func (p *NitroAttestationProvider) GetAttestationDoc(nonce []byte, userData []byte, publicKey []byte) ([]byte, error) {
	return GetAttestationDoc(nonce, userData, publicKey)
}

func GetAttestationDoc(nonce, userData, publicKey []byte) ([]byte, error) {
	sess, err := nsm.OpenDefaultSession()
	defer func(sess *nsm.Session) {
		err := sess.Close()
		if err != nil {

		}
	}(sess)

	if err != nil {
		return nil, err
	}

	res, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  userData,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, err
	}

	if res.Error != "" {
		return nil, errors.New(string(res.Error))
	}

	if nil == res.Attestation || nil == res.Attestation.Document {
		return nil, errors.New("NSM device did not return an attestation")
	}

	return res.Attestation.Document, nil
}
