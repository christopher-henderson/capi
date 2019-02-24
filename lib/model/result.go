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
	SubjectURL  string
	Expectation string
	Chain       ChainResult
	Opinion     Opinion
	Error       string
}

type ChainResult struct {
	Leaf          CertificateResult
	Intermediates []CertificateResult
	Root          CertificateResult
}

type Opinion struct {
	Bad      bool // Whether this opinion thinks the run is bad in some way.
	Errors   []Concern
	Warnings []Concern
	Info     []Concern
}

func (o *Opinion) Append(other Opinion) {
	o.Errors = append(o.Errors, other.Errors...)
	o.Warnings = append(o.Warnings, other.Warnings...)
	o.Info = append(o.Info, other.Info...)
}

type Concern struct {
	Raw            string // The raw response from, say, the OCSP or certutil tools
	Interpretation string // What this tool thinks is wrong.
	Advise         string // Any advise for troubleshooting
}

type CertificateResult struct {
	*x509.Certificate `json:"-"`
	Fingerprint       string
	CrtSh             string
	CommonName        string
	OCSP              []ocsp.OCSP
	CRL               []crl.CRL
	Expiration        expiration.ExpirationStatus
}

func NewCeritifcateResult(certificate *x509.Certificate, ocspResonse []ocsp.OCSP, crlStatus []crl.CRL, expirationStatus expiration.ExpirationStatus) CertificateResult {
	return CertificateResult{
		certificate,
		certificateUtils.FingerprintOf(certificate),
		"https://crt.sh/?q=" + certificateUtils.FingerprintOf(certificate),
		certificate.Subject.CommonName,
		ocspResonse,
		crlStatus,
		expirationStatus,
	}
}
