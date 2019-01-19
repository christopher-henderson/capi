/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package model

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/mozilla/capi/lib/expiration"
	"github.com/mozilla/capi/lib/revocation/crl"
	"github.com/mozilla/capi/lib/revocation/ocsp"
)

type TestWebsiteResult struct {
	SubjectURL string
	Chain      ChainResult
	Error      error
}

type ChainResult struct {
	Leaf          CertificateResult
	Intermediates []CertificateResult
	Root          CertificateResult
	BrokenEdges   [][2]Fingerprint
}

type CertificateResult struct {
	*x509.Certificate `json:"-"`
	Fingerprint       string
	CommonName        string
	OCSP              []ocsp.OCSP
	CRL               []crl.CRL
	Expiration        expiration.ExpirationStatus
}

func NewCeritifcateResult(certificate *x509.Certificate, ocspResonse []ocsp.OCSP, crlStatus []crl.CRL, expirationStatus expiration.ExpirationStatus) CertificateResult {
	return CertificateResult{
		certificate,
		fingerprintOf(certificate),
		certificate.Subject.CommonName,
		ocspResonse,
		crlStatus,
		expirationStatus,
	}
}

type Fingerprint = string

func fingerprintOf(cert *x509.Certificate) Fingerprint {
	hasher := crypto.SHA256.New()
	hasher.Write(cert.Raw)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

//type OCSPResponse struct {
//	Responder string
//	Good      bool
//	Revoked   bool
//	Unknown   bool
//	Error     error
//}
//
////https://tools.ietf.org/html/rfc5280#section-5
//type CRLStatus struct {
//	Endpoint string
//	Revoked  bool
//	Error    error
//}
//
//type ExpirationStatus struct {
//	Valid   bool
//	Expired bool
//	Error   error
//}
//
//type CertificateResultOld struct {
//	Certificate   *x509.Certificate `json:"-"`
//	Subject       string
//	Fingerprint   Fingerprint
//	CRLStatuses   []string
//	OCSPResponses map[ocsp.Responder]ocsp.Response
//	Lint          []string
//	Validation    string
//}
//
//func NewCertificateResult(cert *x509.Certificate) *CertificateResultOld {
//	return &CertificateResultOld{
//		Certificate:   cert,
//		Subject:       cert.Subject.String(),
//		Fingerprint:   fingerprintOf(cert),
//		CRLStatuses:   make([]string, 0),
//		OCSPResponses: make(map[ocsp.Responder]ocsp.Response, 0),
//		Lint:          make([]string, 0),
//		Validation:    "",
//	}
//}
//
//type Fingerprint = string
//
//func fingerprintOf(cert *x509.Certificate) Fingerprint {
//	hasher := crypto.SHA256.New()
//	hasher.Write(cert.Raw)
//	return fmt.Sprintf("%x", hasher.Sum(nil))
//}
