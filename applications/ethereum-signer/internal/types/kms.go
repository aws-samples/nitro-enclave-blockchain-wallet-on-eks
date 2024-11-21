package types

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type KeyTransRecipientInfo struct {
	Version                int
	Rid                    asn1.RawValue `asn1:"choice"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type EnvelopedDataStruct struct {
	Version              int
	RecipientInfos       []KeyTransRecipientInfo `asn1:"set"`
	EncryptedContentInfo struct {
		ContentType                asn1.ObjectIdentifier
		ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedContent           []byte `asn1:"explicit,tag:0"`
	}
}
