package model

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/mozilla/capi/lib/certificateUtils"
)

type CCADBRecords struct {
	CertificateDetails []CCADBRecord
}

type CCADBRecord struct {
	RecordID           string
	Name               string
	PEM                *x509.Certificate
	TestWebsiteValid   string
	TestWebsiteRevoked string
	TestWebsiteExpired string
}

type intermediateRepresentation struct {
	RecordID           string
	Name               string
	PEM                string
	TestWebsiteValid   string
	TestWebsiteRevoked string
	TestWebsiteExpired string
}

func (c *CCADBRecord) UnmarshalJSON(data []byte) (err error) {
	var i intermediateRepresentation
	err = json.Unmarshal(data, &i)
	if err != nil {
		return
	}
	p, err := certificateUtils.NormalizePEM([]byte(i.PEM))
	if err != nil {
		return
	}
	block, _ := pem.Decode(p)
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	c.RecordID = i.RecordID
	c.Name = i.Name
	c.PEM = root
	c.TestWebsiteValid = i.TestWebsiteValid
	c.TestWebsiteRevoked = i.TestWebsiteRevoked
	c.TestWebsiteExpired = i.TestWebsiteExpired
	return
}
