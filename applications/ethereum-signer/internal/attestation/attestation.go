package attestation

import (
	"errors"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

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

	//var attestationDocB64 []byte
	//base64.StdEncoding.Encode(attestationDocB64, res.Attestation.Document)

	return res.Attestation.Document, nil
}
