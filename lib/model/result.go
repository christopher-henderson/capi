/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package model

import (
	"crypto/x509"
	"github.com/mozilla/capi/lib/certificateUtils"
	"github.com/mozilla/capi/lib/expiration"
	"github.com/mozilla/capi/lib/revocation/crl"
	"github.com/mozilla/capi/lib/revocation/ocsp"
)

type TestWebsiteResult struct {
	SubjectURL string
	Chain      ChainResult
	Error      string
}

type ChainResult struct {
	Leaf          CertificateResult
	Intermediates []CertificateResult
	Root          CertificateResult
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
		certificateUtils.FingerprintOf(certificate),
		certificate.Subject.CommonName,
		ocspResonse,
		crlStatus,
		expirationStatus,
	}
}
