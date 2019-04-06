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
	switch expectation {
	case Valid:
		//////// Expiration checks
		// Leaf must NOT be expired
		result.Opinion.Append(assertNotExpired(result.Chain.Leaf, Leaf))
		// Intermediates must NOT be expired
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertNotExpired(intermediate, Intermediate))
		}
		// Root must NOT be expired.
		result.Opinion.Append(assertNotExpired(result.Chain.Root, Root))
		/////// Revocation checks
		// Leaf MUST be Good
		result.Opinion.Append(assertNotRevoked(result.Chain.Leaf, Leaf))
		// Intermediates MUST be Good.
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertNotRevoked(intermediate, Intermediate))
		}
		// Root must be Good
		result.Opinion.Append(assertNotRevoked(result.Chain.Root, Root))
	case Expired:
		//////// Expiration checks
		// Leaf MUST be expired
		result.Opinion.Append(assertExpired(result.Chain.Leaf, Leaf))
		// Intermediates MAY be expired
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertMayBeExpired(intermediate, Intermediate))
		}
		// Root must NOT be expired.
		result.Opinion.Append(assertNotExpired(result.Chain.Root, Root))
		/////// Revocation checks
		// Leaf may be either Good or Unauthorized
		result.Opinion.Append(assertNotRevoked(result.Chain.Leaf, Leaf))
		// Intermediates may be good (or Unauthorized iff they are expired)
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertNotRevoked(intermediate, Intermediate))
		}
		// Root must be Good
		result.Opinion.Append(assertNotRevoked(result.Chain.Root, Root))
	case Revoked:
		//////// Expiration checks
		// Leaf must not be expired.
		result.Opinion.Append(assertNotExpired(result.Chain.Leaf, Leaf))
		// Intermediates must not be expired
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertNotExpired(intermediate, Intermediate))
		}
		// Root must not be expired
		result.Opinion.Append(assertNotExpired(result.Chain.Root, Root))
		/////// Revocation checks
		// Leaf MUST be revoked.
		result.Opinion.Append(assertRevoked(result.Chain.Leaf, Leaf))
		// Intermediates MAY be revoked
		for _, intermediate := range result.Chain.Intermediates {
			result.Opinion.Append(assertMayBeRevoked(intermediate, Intermediate))
		}
		// Root must NOT be revoked
		result.Opinion.Append(assertNotRevoked(result.Chain.Root, Root))
	}

	if len(result.Opinion.Errors) != 0 {
		result.Opinion.Bad = true
	}
}

type CertType string

const (
	Root         CertType = "root"
	Intermediate          = "intermediate"
	Leaf                  = "leaf"
)

func assertNotRevoked(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	for _, response := range cert.OCSP {
		if cert.Expiration.Status == expiration.Expired && response.Status == ocsp.Unauthorized && t != Root {
			continue
		}
		if response.Status != ocsp.Good {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw: "",
				Interpretation: fmt.Sprintf(
					"Got OCSP response %s, wanted %s. OCSP responder was %s.Fingerprint %s",
					response.Status.String(), "good", response.Responder, cert.Fingerprint),
				Advise: cert.CrtSh,
			})
		}
		if response.Error != "" {
			opinion.Errors = append(opinion.Errors, model.Concern{
				Raw:            response.Error,
				Interpretation: fmt.Sprintf("An error occurred while retrieving the OCSP status of the %s. This is usually a networking error", t),
				Advise:         fmt.Sprintf(cert.CrtSh),
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

//func assertNoRevocationIssues(cert model.CertificateResult, t CertType, e Expectation) (opinion model.Opinion) {
//	for _, response := range cert.OCSP {
//		if strings.Contains(response.Error, "unsupported protocol scheme \"ldap\"") {
//			log.Error(response.Error)
//			continue
//		}
//		if e == Expired && response.Status == ocsp.Unauthorized {
//			continue
//		}
//		if response.Status != ocsp.Good {
//			opinion.Errors = append(opinion.Errors, model.Concern{
//				Raw: "",
//				Interpretation: fmt.Sprintf(
//					"OCSP responder %s does not believe that the %s certificate, %s, is good. Result was %s",
//					response.Responder, t, cert.Fingerprint, response.Status.String()),
//				Advise: cert.CrtSh,
//			})
//		}
//		if response.Error != "" {
//			opinion.Errors = append(opinion.Errors, model.Concern{
//				Raw:            response.Error,
//				Interpretation: fmt.Sprintf("An error occurred while retrieving the OCSP status of the %s. This is usually a networking error", t),
//				Advise:         fmt.Sprintf("If this is a networking error, attempt to verify that OCSP responder at %s is active and available", response.Responder),
//			})
//		}
//	}
//	for _, crlStatus := range cert.CRL {
//		if strings.Contains(crlStatus.Error, "unsupported protocol scheme \"ldap\"") {
//			// Silencing the bug that we haven't supported LDAP endpoints yet.
//			log.Error(crlStatus.Error)
//			continue
//		}
//		if crlStatus.Revoked {
//			opinion.Errors = append(opinion.Errors, model.Concern{
//				Raw: "",
//				Interpretation: fmt.Sprintf(
//					"CRL endpoint at %s lists the %s certificate, %s, as revoked.",
//					crlStatus.Endpoint, t, cert.Fingerprint),
//				Advise: cert.CrtSh,
//			})
//		}
//		if crlStatus.Error != "" {
//			opinion.Errors = append(opinion.Errors, model.Concern{
//				Raw:            crlStatus.Error,
//				Interpretation: "An error occurred while retrieving the CRL. This is usually a networking error",
//				Advise:         fmt.Sprintf("If this is a networking error, attempt to verify that CRL endpoint at %s is active and available", crlStatus.Endpoint),
//			})
//		}
//	}
//	return
//}

//func assertNoExpirationIssues(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
//	if cert.Expiration.Status == expiration.Expired {
//		opinion.Errors = append(opinion.Errors, model.Concern{
//			Raw: cert.Expiration.Raw,
//			Interpretation: fmt.Sprintf("certutil believes that the %s certificate, %s, is expired",
//				t, cert.Fingerprint),
//			Advise: cert.CrtSh,
//		})
//	}
//	if cert.Expiration.Status == expiration.IssuerUnknown {
//		opinion.Errors = append(opinion.Errors, model.Concern{
//			Raw: cert.Expiration.Raw,
//			Interpretation: fmt.Sprintf("certutil believes that the provided chain is broken for the %s certificate %s",
//				t, cert.Fingerprint),
//			Advise: cert.CrtSh,
//		})
//	}
//	if cert.Expiration.Error != "" {
//		opinion.Errors = append(opinion.Errors, model.Concern{
//			Raw: cert.Expiration.Raw,
//			Interpretation: fmt.Sprintf("certutil encountered a fatal error when attempting to verify the %s certificate, %s",
//				t, cert.Fingerprint),
//			Advise: "This is likely an error in CAPI",
//		})
//	}
//	return
//}

func assertNotExpired(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	if cert.Expiration.Status == expiration.Expired {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw:            cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("%s is expired", t),
			Advise:         cert.CrtSh,
		})
	}
	if cert.Expiration.Status == expiration.IssuerUnknown {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw:            cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("Bad chain at %s", t),
			Advise:         cert.CrtSh,
		})
	}
	if cert.Expiration.Error != "" {
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw:            cert.Expiration.Raw,
			Interpretation: fmt.Sprintf("fatal error at %s", t),
			Advise:         cert.CrtSh,
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

func assertMayBeExpired(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
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
		if response.Status == ocsp.Revoked {
			continue
		}
		opinion.Errors = append(opinion.Errors, model.Concern{
			Raw:            response.Status.String(),
			Interpretation: fmt.Sprintf("%s is not revoked, responder %s", t, response.Responder),
			Advise:         cert.CrtSh,
		})
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

func assertMayBeRevoked(cert model.CertificateResult, t CertType) (opinion model.Opinion) {
	for _, response := range cert.OCSP {
		if strings.Contains(response.Error, "unsupported protocol scheme \"ldap\"") {
			log.Error(response.Error)
			continue
		}
		if response.Status == ocsp.Revoked {
			continue
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
