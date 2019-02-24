package service

import (
	"fmt"
	"github.com/mozilla/capi/lib/expiration"
	"github.com/mozilla/capi/lib/model"
	"github.com/mozilla/capi/lib/revocation/ocsp"
	log "github.com/sirupsen/logrus"
	"strings"
)

type Expectation int

const (
	None Expectation = iota
	Valid
	Expired
	Revoked
)

func (e Expectation) String() string {
	switch e {
	case None:
		return "none"
	case Valid:
		return "valid"
	case Expired:
		return "expired"
	case Revoked:
		return "revoked"
	}
	return ""
}

func InterpretResult(result *model.TestWebsiteResult, expectation Expectation) {
	rootRevocation(result)
	intermediateRevocation(result)

	rootExpiration(result)
	intermediateExpriation(result)

	switch expectation {
	case Valid:
		opinion := assertNoExpirationIssues(result.Chain.Leaf, Leaf)
		result.Opinion.Append(opinion)

		opinion = assertNoRevocationIssues(result.Chain.Leaf, Leaf)
		result.Opinion.Append(opinion)
	case Expired:
		opinion := assertExpired(result.Chain.Leaf, Leaf)
		result.Opinion.Append(opinion)

		opinion = assertNoRevocationIssues(result.Chain.Leaf, Leaf)
		result.Opinion.Append(opinion)
	case Revoked:
		opinion := assertRevoked(result.Chain.Leaf, Leaf)
		result.Opinion.Append(opinion)

		opinion = assertNoExpirationIssues(result.Chain.Leaf, Leaf)
		result.Opinion.Errors = append(result.Opinion.Errors, opinion.Errors...)
		result.Opinion.Warnings = append(result.Opinion.Warnings, opinion.Warnings...)
		result.Opinion.Info = append(result.Opinion.Info, opinion.Info...)
	}

	if len(result.Opinion.Errors) != 0 {
		result.Opinion.Bad = true
	}
}

// These are errors
func rootRevocation(result *model.TestWebsiteResult) {
	opinion := assertNoRevocationIssues(result.Chain.Root, Root)
	result.Opinion.Append(opinion)
}

func rootExpiration(result *model.TestWebsiteResult) {
	opinion := assertNoExpirationIssues(result.Chain.Root, Root)
	result.Opinion.Append(opinion)
}

func intermediateRevocation(result *model.TestWebsiteResult) {
	for _, intermediate := range result.Chain.Intermediates {
		opinion := assertNoRevocationIssues(intermediate, Intermediate)
		result.Opinion.Append(opinion)
	}
}

func intermediateExpriation(result *model.TestWebsiteResult) {
	for _, intermediate := range result.Chain.Intermediates {
		opinion := assertNoExpirationIssues(intermediate, Intermediate)
		result.Opinion.Append(opinion)
	}
}

type CertType string

const (
	Root         CertType = "root"
	Intermediate          = "intermediate"
	Leaf                  = "leaf"
)

func assertNoRevocationIssues(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	for _, response := range cert.OCSP {
		if strings.Contains(response.Error, "unsupported protocol scheme \"ldap\"") {
			log.Error(response.Error)
			continue
		}
		if response.Status != ocsp.Good {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw: "",
				Interpretation: fmt.Sprintf(
					"OCSP responder %s does not believe that the %s certificate, %s, is good. Result was %s",
					response.Responder, t, cert.Fingerprint, response.Status.String()),
				Advise: cert.CrtSh,
			})
		}
		if response.Error != "" {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            response.Error,
				Interpretation: fmt.Sprintf("An error occurred while retrieving the OCSP status of the %s. This is usually a networking error", t),
				Advise:         fmt.Sprintf("If this is a networking error, attempt to verify that OCSP responder at %s is active and available", response.Responder),
			})
		}
	}
	for _, crlStatus := range cert.CRL {
		if strings.Contains(crlStatus.Error, "unsupported protocol scheme \"ldap\"") {
			// Silencing the bug that we haven't supported LDAP endpoints yet.
			log.Error(crlStatus.Error)
			continue
		}
		if crlStatus.Revoked {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw: "",
				Interpretation: fmt.Sprintf(
					"CRL endpoint at %s lists the %s certificate, %s, as revoked.",
					crlStatus.Endpoint, t, cert.Fingerprint),
				Advise: cert.CrtSh,
			})
		}
		if crlStatus.Error != "" {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            crlStatus.Error,
				Interpretation: "An error occurred while retrieving the CRL. This is usually a networking error",
				Advise:         fmt.Sprintf("If this is a networking error, attempt to verify that CRL endpoint at %s is active and available", crlStatus.Endpoint),
			})
		}
	}
	return
}

func assertNoExpirationIssues(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	if cert.Expiration.Status == expiration.Expired {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw: cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("certutil believes that the %s certificate, %s, is expired",
				t, cert.Fingerprint),
			Advise: cert.CrtSh,
		})
	}
	if cert.Expiration.Status == expiration.IssuerUnknown {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw: cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("certutil believes that the provided chain is broken for the %s certificate %s",
				t, cert.Fingerprint),
			Advise: cert.CrtSh,
		})
	}
	if cert.Expiration.Error != "" {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw: cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("certutil encountered a fatal error when attempting to verify the %s certificate, %s",
				t, cert.Fingerprint),
			Advise: "This is likely an error in CAPI",
		})
	}
	return
}

func assertExpired(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	if cert.Expiration.Status != expiration.Expired {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw: cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("certutil does not believe that the %s certificate, %s, is expired",
				t, cert.Fingerprint),
			Advise: cert.CrtSh,
		})
	}
	if cert.Expiration.Status == expiration.IssuerUnknown {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw: cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("certutil believes that the provided chain is broken for the %s certificate %s",
				t, cert.Fingerprint),
			Advise: cert.CrtSh,
		})
	}
	if cert.Expiration.Error != "" {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw: cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("certutil encountered a fatal error when attempting to verify the %s certificate, %s",
				t, cert.Fingerprint),
			Advise: "This is likely an error in CAPI",
		})
	}
	return
}

func assertRevoked(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	for _, response := range cert.OCSP {
		if strings.Contains(response.Error, "unsupported protocol scheme \"ldap\"") {
			log.Error(response.Error)
			continue
		}
		if response.Status != ocsp.Revoked {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw: "",
				Interpretation: fmt.Sprintf(
					"OCSP responder %s does not believe that the %s certificate, %s, is revoked. Result was %s",
					response.Responder, t, cert.Fingerprint, response.Status.String()),
				Advise: cert.CrtSh,
			})
		}
		if response.Error != "" {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            response.Error,
				Interpretation: fmt.Sprintf("An error occurred while retrieving the OCSP status of the %s. This is usually a networking error", t),
				Advise:         fmt.Sprintf("If this is a networking error, attempt to verify that OCSP responder at %s is active and available", response.Responder),
			})
		}
	}
	for _, crlStatus := range cert.CRL {
		if strings.Contains(crlStatus.Error, "unsupported protocol scheme \"ldap\"") {
			log.Error(crlStatus.Error)
			continue
		}
		if !crlStatus.Revoked {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw: "",
				Interpretation: fmt.Sprintf(
					"CRL endpoint at %s lists the %s certificate, %s, as not revoked.",
					crlStatus.Endpoint, t, cert.Fingerprint),
				Advise: cert.CrtSh,
			})
		}
		if crlStatus.Error != "" {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            crlStatus.Error,
				Interpretation: "An error occurred while retrieving the CRL. This is usually a networking error",
				Advise:         fmt.Sprintf("If this is a networking error, attempt to verify that CRL endpoint at %s is active and available", crlStatus.Endpoint),
			})
		}
	}
	return
}

func leafNotAsExpected(leaf model.CertificateResult, expectation Expectation) {

}
