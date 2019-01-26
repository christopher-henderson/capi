/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package expiration

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/mozilla/capi/lib/expiration/certutil"
)

func TestTheTestersSplittingFunction(t *testing.T) {
	certs := parseChain(validChain)
	if len(certs) != 3 {
		t.Fatalf("wanted 3 parsed certificates, got %d\n", len(certs))
	}
}

func parseChain(chain string) (certs []*x509.Certificate) {
	for _, b := range strings.SplitAfter(chain, "-----END CERTIFICATE-----") {
		if len(b) == 0 {
			continue
		}
		block, rest := pem.Decode([]byte(b))
		if len(rest) != 0 {
			panic("dangling info on a certificate: " + string(rest))
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
		certs = append(certs, cert)
	}
	return
}

// Chambers of Commerce Root
var expiredChain = `-----BEGIN CERTIFICATE-----
MIIGfDCCBWSgAwIBAgIJHkFSnaq9vuFUMA0GCSqGSIb3DQEBCwUAMIH9MQswCQYD
VQQGEwJFUzEiMCAGCSqGSIb3DQEJARYTaW5mb0BjYW1lcmZpcm1hLmNvbTFDMEEG
A1UEBxM6TWFkcmlkIChzZWUgY3VycmVudCBhZGRyZXNzIGF0IHd3dy5jYW1lcmZp
cm1hLmNvbS9hZGRyZXNzKTESMBAGA1UEBRMJQTgyNzQzMjg3MSIwIAYDVQQLExlo
dHRwOi8vd3d3LmNhbWVyZmlybWEuY29tMRkwFwYDVQQKExBBQyBDYW1lcmZpcm1h
IFNBMTIwMAYDVQQDEylBQyBDYW1lcmZpcm1hIEV4cHJlc3MgQ29ycG9yYXRlIFNl
cnZlciB2MzAeFw0xODAxMTcwODA4MTFaFw0xODAxMTgwODA4MTFaMIGDMQ8wDQYD
VQQHDAZNQURSSUQxEjAQBgNVBAUTCUE4Mjc0MzI4NzERMA8GA1UECwwIU0lTVEVN
QVMxGzAZBgNVBAoMEkFDIENBTUVSRklSTUEgUy5BLjEfMB0GA1UEAwwWc2VydmVy
MS5jYW1lcmZpcm1hLmNvbTELMAkGA1UEBhMCRVMwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCp3x3FIp+RR1j78a+l4qQZKbJotw5jB2cO8Tg5PUfQrYPv
MLTvZq8CYlRVSDds+LNmVARRjeZiqb9/DWOeGqJ9hy60GM6J5T5gsQV62bzd554H
NRu1GPGFEUuGIjUbNXcpvumGd5vTLfN6Z4V6Ki81y/JqOEre+nO1lxlB+LmKnXri
s96ErkVOejOkCFUOaLJEzkZogDtODgNsCbggoGFkgpfVWtuXsgE7s+CmrbQkEqRs
QsG2xXtlpTOiz/DAggS976LyeZITYZBwm13rkqhcMDiONsAneoVbpe4uiUsdrJVS
IvfF64euKriRPvvOhs5JIvCK63mAlUbZ3INOXC55AgMBAAGjggJ1MIICcTAMBgNV
HRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwHQYDVR0OBBYEFA4ZjJvWI8eifDa7q03proEt45WhMBMGCisGAQQB
1nkCBAIEBQSBAgAAMHEGCCsGAQUFBwEBBGUwYzA5BggrBgEFBQcwAoYtaHR0cDov
L3d3dy5jYW1lcmZpcm1hLmNvbS9jZXJ0cy9DTUZFQ1NfdjMuY3J0MCYGCCsGAQUF
BzABhhpodHRwOi8vb2NzcC5jYW1lcmZpcm1hLmNvbTCBqwYDVR0jBIGjMIGggBQK
SsDKmBLvl1nd96SvsBSkOa6uSqGBhKSBgTB/MQswCQYDVQQGEwJFVTEnMCUGA1UE
ChMeQUMgQ2FtZXJmaXJtYSBTQSBDSUYgQTgyNzQzMjg3MSMwIQYDVQQLExpodHRw
Oi8vd3d3LmNoYW1iZXJzaWduLm9yZzEiMCAGA1UEAxMZQ2hhbWJlcnMgb2YgQ29t
bWVyY2UgUm9vdIIBCjBoBgNVHR8EYTBfMC2gK6AphidodHRwOi8vY3JsLmNhbWVy
ZmlybWEuY29tL2NtZmVjc192My5jcmwwLqAsoCqGKGh0dHA6Ly9jcmwxLmNhbWVy
ZmlybWEuY29tL2NtZmVjc192My5jcmwwIQYDVR0RBBowGIIWc2VydmVyMS5jYW1l
cmZpcm1hLmNvbTBQBgNVHSAESTBHMDsGDCsGAQQBgYcuCgsCATArMCkGCCsGAQUF
BwIBFh1odHRwczovL3BvbGljeS5jYW1lcmZpcm1hLmNvbTAIBgZngQwBAgIwDQYJ
KoZIhvcNAQELBQADggEBAAwhPZX+4Ub4Rcus2wQS7cORLEYq1CH2QYCnRLxQjmyI
v38PKYJkcMsLfK4We3+CHEqaGvFzLXmCNrL/aE1Irq70/Iv0d2V1lY5L/afh8+Xm
NNaxSpEidHlF/vSWGy87a3B6YtRwHau+0XbIeley0Rw8Fw2ESGOG/iplN7+syl6k
vwSRSA30xmGn129B9uwV1E/tMPsopb/6qvSA48OdiAEU1IUlZjGa6QFpKBHIYYtf
aboGym5+H+GZWVXmSVSi/EKigFSJ+PM7+rLWbUWn8XtNGKF0yawe8u0n4e39AB2G
apTSBs86txAfLTORaFe7G9ClBaP248sML740rZWAcWw=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGXDCCBUSgAwIBAgIBCjANBgkqhkiG9w0BAQUFADB/MQswCQYDVQQGEwJFVTEn
MCUGA1UEChMeQUMgQ2FtZXJmaXJtYSBTQSBDSUYgQTgyNzQzMjg3MSMwIQYDVQQL
ExpodHRwOi8vd3d3LmNoYW1iZXJzaWduLm9yZzEiMCAGA1UEAxMZQ2hhbWJlcnMg
b2YgQ29tbWVyY2UgUm9vdDAeFw0wOTAxMjAxMDE4MTJaFw0xOTAxMTgxMDE4MTJa
MIH9MQswCQYDVQQGEwJFUzEiMCAGCSqGSIb3DQEJARYTaW5mb0BjYW1lcmZpcm1h
LmNvbTFDMEEGA1UEBxM6TWFkcmlkIChzZWUgY3VycmVudCBhZGRyZXNzIGF0IHd3
dy5jYW1lcmZpcm1hLmNvbS9hZGRyZXNzKTESMBAGA1UEBRMJQTgyNzQzMjg3MSIw
IAYDVQQLExlodHRwOi8vd3d3LmNhbWVyZmlybWEuY29tMRkwFwYDVQQKExBBQyBD
YW1lcmZpcm1hIFNBMTIwMAYDVQQDEylBQyBDYW1lcmZpcm1hIEV4cHJlc3MgQ29y
cG9yYXRlIFNlcnZlciB2MzCCASAwDQYJKoZIhvcNAQEBBQADggENADCCAQgCggEB
AIg1c+SE9a2pYYPrVGr9c+aEjvoUncE2WhlZhuKzfxwF5YSV1UfGmPupAgy1yILQ
cTUd2M2bqCzInVZ0aLJQ5MmmG0dfzq4EFh/apTyTMcNrfoN9ocafuEwCYxLAyhh9
JHqRyOzkjWLpyI2Xw1w5vTWESGVNDVcAm5eEMIGSnWsLqjOJaXd4QwXvy4CQi//j
FRIZD2nP6xyJlLHdYxpbfETAqyea4loU+E0oy5PxJQlB9xE7BqmmpviV2SHFTPd/
VnX9/AAJPOM0bEvVCauDojwLCqp+8N+rEEaAnO8U2c4N3lZVuRXkc9ykg7hSkABh
cMDOyMdfS8aeGNdNG7lMzFECAQOjggJkMIICYDASBgNVHRMBAf8ECDAGAQH/AgEC
MG4GA1UdHwRnMGUwMKAuoCyGKmh0dHA6Ly9jcmwuY2FtZXJmaXJtYS5jb20vY2hh
bWJlcnNyb290LmNybDAxoC+gLYYraHR0cDovL2NybDEuY2FtZXJmaXJtYS5jb20v
Y2hhbWJlcnNyb290LmNybDAdBgNVHQ4EFgQUCkrAypgS75dZ3fekr7AUpDmurkow
dQYIKwYBBQUHAQEEaTBnMD0GCCsGAQUFBzAChjFodHRwOi8vd3d3LmNhbWVyZmly
bWEuY29tL2NlcnRzL1JPT1QtQ0hBTUJFUlMuY3J0MCYGCCsGAQUFBzABhhpodHRw
Oi8vb2NzcC5jYW1lcmZpcm1hLmNvbTCBqwYDVR0jBIGjMIGggBTjlPWxTenboSlb
V4tNdgZ24dGiiqGBhKSBgTB/MQswCQYDVQQGEwJFVTEnMCUGA1UEChMeQUMgQ2Ft
ZXJmaXJtYSBTQSBDSUYgQTgyNzQzMjg3MSMwIQYDVQQLExpodHRwOi8vd3d3LmNo
YW1iZXJzaWduLm9yZzEiMCAGA1UEAxMZQ2hhbWJlcnMgb2YgQ29tbWVyY2UgUm9v
dIIBADAOBgNVHQ8BAf8EBAMCAQYwHgYDVR0RBBcwFYETaW5mb0BjYW1lcmZpcm1h
LmNvbTAnBgNVHRIEIDAegRxjaGFtYmVyc3Jvb3RAY2hhbWJlcnNpZ24ub3JnMD0G
A1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwOi8vcG9saWN5LmNh
bWVyZmlybWEuY29tMA0GCSqGSIb3DQEBBQUAA4IBAQAw33XPOfeYIQuMozpM10jQ
4QtoJC+GeZUuAuMw0Yg+Klhipr+gOx6nHmpnNptChWcad97BZdY1xQPcGUmHXHBg
E1QOMDE5e7lakHyhs2su0QK6fFTFC+xhWr5gGY9fxS6JFwzOrYIEV9hktMl9Z/K0
/Z5beZ4vocqq47R/R3pem5d1YSGviayQrjKsWdTUZTk57p+oKb3QhuRhRS80tOTT
9xmhmt3YwUUT+FZhBPPfrlZtJb3PDNVCjgYyBynDj7VjIsfGxZgogisO+84LhEp2
UcXy2I2PbqLy7XRzPRxJKcRgbooFzC9iuY5ZcFJB9JLqo57rtZimNjNwLoO8sifX
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEvTCCA6WgAwIBAgIBADANBgkqhkiG9w0BAQUFADB/MQswCQYDVQQGEwJFVTEn
MCUGA1UEChMeQUMgQ2FtZXJmaXJtYSBTQSBDSUYgQTgyNzQzMjg3MSMwIQYDVQQL
ExpodHRwOi8vd3d3LmNoYW1iZXJzaWduLm9yZzEiMCAGA1UEAxMZQ2hhbWJlcnMg
b2YgQ29tbWVyY2UgUm9vdDAeFw0wMzA5MzAxNjEzNDNaFw0zNzA5MzAxNjEzNDRa
MH8xCzAJBgNVBAYTAkVVMScwJQYDVQQKEx5BQyBDYW1lcmZpcm1hIFNBIENJRiBB
ODI3NDMyODcxIzAhBgNVBAsTGmh0dHA6Ly93d3cuY2hhbWJlcnNpZ24ub3JnMSIw
IAYDVQQDExlDaGFtYmVycyBvZiBDb21tZXJjZSBSb290MIIBIDANBgkqhkiG9w0B
AQEFAAOCAQ0AMIIBCAKCAQEAtzZV5aVdGDDg2olUkfzIx1L4L1DZ77F1c2VHfRtb
unXF/KGIJPov7coISjlUxFF6tdpg6jg8gbLL8bvZkSM/SAFwdakFKq0fcfPJVD0d
BmpAPrMMhe5cG3nCYsS4No41XQEMIwRHNaqbYE6gZj3LJgqcQKH0XZi/caulAGgq
7YN6D6IUtdQis4CwPAxaUWktWBiP7Zme8a7ileb2R6jWDA+wWFjbw2Y3npuRVDM3
0pQcakjJyfKl2qUMI/cjDpwyVV5xnIQFUZot/eZOKjRa3spAN2cMVCFVd9oKDMyX
roDclDZK9D7ONhMeU+SsTjoF7Nuucpw4i9A5O4kKPnf+dQIBA6OCAUQwggFAMBIG
A1UdEwEB/wQIMAYBAf8CAQwwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5j
aGFtYmVyc2lnbi5vcmcvY2hhbWJlcnNyb290LmNybDAdBgNVHQ4EFgQU45T1sU3p
26EpW1eLTXYGduHRooowDgYDVR0PAQH/BAQDAgEGMBEGCWCGSAGG+EIBAQQEAwIA
BzAnBgNVHREEIDAegRxjaGFtYmVyc3Jvb3RAY2hhbWJlcnNpZ24ub3JnMCcGA1Ud
EgQgMB6BHGNoYW1iZXJzcm9vdEBjaGFtYmVyc2lnbi5vcmcwWAYDVR0gBFEwTzBN
BgsrBgEEAYGHLgoDATA+MDwGCCsGAQUFBwIBFjBodHRwOi8vY3BzLmNoYW1iZXJz
aWduLm9yZy9jcHMvY2hhbWJlcnNyb290Lmh0bWwwDQYJKoZIhvcNAQEFBQADggEB
AAxBl8IahsAifJ/7kPMa0QOx7xP5IV8EnNrJpY0nbJaHkb5BkAFyk+cefV/2icZd
p0AJPaxJRUXcLo0waLIJuvvDL8y6C98/d3tGfToSJI6WjzwFCm/SlCgdbQzALogi
1djPHRPH8EjX1wWnz8dHnjs8NMiAT9QUu/wNUPf6s+xCX6ndbcj0dc97wXImsQEc
XCz9ek60AcUFV7nnPKoF2YjpB0ZBzu9Bga5Y34OirsrXdx/nADydb47kMgkdTXg0
eDQ8lJsm7U9xxhl6vSAiSFr+S30Dt+dYvsYyTnQeaN2oaFuzPu5ifdmA6Ap1erfu
tGWaIZDgqtCYvDi1czyL+Nw=
-----END CERTIFICATE-----`

// Amazon Root CA 2
var revokedChain = `-----BEGIN CERTIFICATE-----
MIIGJjCCBA6gAwIBAgITBn+Ub1C6aU7VcBuLNQw6SIwKgDANBgkqhkiG9w0BAQwF
ADBGMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2
ZXIgQ0EgMkExDzANBgNVBAMTBkFtYXpvbjAeFw0xNTEyMDMyMjQwMTJaFw0xOTAz
MDMyMjQwMTJaMCgxJjAkBgNVBAMTHXJldm9rZWQuc2NhMmEuYW1hem9udHJ1c3Qu
Y29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9Bx/cmIVkR5JMUx+
4TeN3bcOFZznmvrLCrkaaLg75dO0VjtI/BtYD0bMNaJtEh4MSWIUB/Nr0EbhcDxP
3W4gYvx+CWDnMKotrG4NRHr+ZgCSZLwKua+0W9JFplYvDdJ27FvnM8aoKVNyytQt
ZSkyU/RFKpIPe+HEjKJoPE5dcfNB0knOT7//RDD+2u1qAnSoN8LvAOCOEqyMykyr
/ZPWMavO3Yij3EuGvUOEB5mM9rzkwhcx6NalOwPhcx1mPzHkRwQKlphTrmrh66Re
096JzE7CUaQ+4zljZN6lDAf7E/C3eWzaMU2dSyLHz3veCKOhWewsgMeZoFILQH4A
6hmeU2DH02y4QztoJqtaeD69Q2XZZPoDy3lQ29ehdZf9RPHGoX4aI97JcVkdNW0j
qtwn7Ice9LyLcTKJNgDtfaowDGXolqR/g2yPIVid8uLs97Ujz7a25MFSZulL1oqS
Y5E06Vy4T6mba/Bz9kIXPq0pYyAKxYFktIVMpZGaTkbTXCHJNvvpD32FLm9ZiYcI
8WxXSbz7fTL+Ty7OF5/GcRLbrDbNS1t7wKps8y55IPrLAs88252ACSVaDHa9Ae1I
Ykr97f5tPVRTuCmTie3SoBsGQwRsC0DfIPsDigeJL8BQDrqK0cUsql5YfDXyWu/3
HRFPDdtAfbq1lGqa3VuvKnrevj8CAwEAAaOCASkwggElMA4GA1UdDwEB/wQEAwIF
oDAdBgNVHQ4EFgQUWM7hEnMT8k8jk/BYafmIHNuRDOgwHwYDVR0jBBgwFoAU2kNK
0PwBwEu/WCeMds0KgfOULvQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYhaHR0cDovL29jc3Auc2NhMmEu
YW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipodHRwOi8vY3J0LnNjYTJhLmFt
YXpvbnRydXN0LmNvbS9zY2EyYS5jZXIwKAYDVR0RBCEwH4IdcmV2b2tlZC5zY2Ey
YS5hbWF6b250cnVzdC5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwDQYJKoZIhvcN
AQEMBQADggIBAGKT7Ghj0MgyRtmjPGW0b/x+KrzS9smgCiCZo6d/MLOngvApWUgg
IPmEDFaI5+kEtdjH1FbFUzhubKCG9Ay/NVCHR062LgUgDAGhwZbD5wdl/mslp3pO
vixqOLTmeOAfknONbtYitWawi0SrpcocUaDhjiVdkTNCahPQNmi4LGMFDcU4V6iA
V4OJljrm2nh9+QfN27UDk1kTLvcsfVUGRjBH209Q5IEvcDxeftLBJkDfaNUgjpHg
wVtmOtKhfB0TU1JQC3fEwbZAxj0ZV5FH05/nIOBrnYLZt5dKyggB5WThz1llETuJ
OLErasUwgblf/yDKayoAgppKkpM717DKiotNzRJhzjuGiNjrBzdprXG5dWXFsd+H
K9l7Uay/3Sbkb10fGWfEvMkLcThCFh7Vfey47gWJEuA3zHVMAxuPbk2ZXjuYkuZo
zOMjPLVNdhtMoDjsUE1kQgojCl8GbFuxedKlsFsBkDdGeZLb6THHL3J3WCMbUYaK
y+cltCCgWzcYNUaA8MQjUo2JIUTDZXXTcQa6eU/8d64P0C+YTJbSimAsKthn/doj
jwajkBdTNsOszsCGHf6O7en98dZ10oyDW8j1mdqYvZz5tcpXENo7zGXaY6Ta+fpJ
JXMFFcmWOojZA/ZbI3Bl1ce4LTrCsiH3KFnyMbZN71uQsihdmwFkJgdm
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGRzCCBC+gAwIBAgITBn+UV1Xxh6kfgWPz5iRiAXf/ODANBgkqhkiG9w0BAQwF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAyMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDJBMQ8wDQYDVQQDEwZBbWF6b24wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQC0P8hSLewmrZ41CCPBQytZs5NBFMq5ztbnMf+kZUp9S25LPfjNW3zgC/6E
qCTWNVMMHhq7ez9IQJk48qbfBTLlZkuKnUWbA9vowrDfcxUN0mRE4B/TJbveXyTf
vE91iDlqDrERecE9D8sdjzURrtHTp27lZdRkXFvfEVCq4hl3sHkzjodisaQthLp1
gLsiA7vKt+8zcL4Aeq52UyYb8r4/jdZ3KaQp8O/T4VwDCRKm8ey3kttpJWaflci7
eRzNjY7gE3NMANVXCeQwOBfH2GjINFCObmPsqiBuoAnsv2k5aQLNoU1OZk08ClXm
mEZ2rI5qZUTX1HuefBJnpMkPugFCw8afaHnB13SkLE7wxX8SZRdDIe5WiwyDL1tR
2+8lpz4JsMoFopHmD3GaHyjbN+hkOqHgLltwewOsiyM0u3CZphypN2KeD+1FLjnY
TgdIAd1FRgK2ZXDDrEdjnsSEfShKf0l4mFPSBs9E3U6sLmubDRXKLLLpa/dF4eKu
LEKS1bXYT28iM6D5gSCnzho5G4d18jQD/slmc5XmRo5Pig0RyBwDaLuxeIZuiJ0A
J6YFhffbrLYF5dEQl0cU+t3VBK5u/o1WkWXsZawU038lWn/AXerodT/pAcrtWA4E
NQEN09WEKMhZVPhqdwhF/Gusr04mQtKt7T2v6UMQvtVglv5E7wIDAQABo4IBOTCC
ATUwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYE
FNpDStD8AcBLv1gnjHbNCoHzlC70MB8GA1UdIwQYMBaAFLAM8Eww9AVYAkj9M+VS
r0uE42ZSMHsGCCsGAQUFBwEBBG8wbTAvBggrBgEFBQcwAYYjaHR0cDovL29jc3Au
cm9vdGNhMi5hbWF6b250cnVzdC5jb20wOgYIKwYBBQUHMAKGLmh0dHA6Ly9jcnQu
cm9vdGNhMi5hbWF6b250cnVzdC5jb20vcm9vdGNhMi5jZXIwPwYDVR0fBDgwNjA0
oDKgMIYuaHR0cDovL2NybC5yb290Y2EyLmFtYXpvbnRydXN0LmNvbS9yb290Y2Ey
LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBAEO5W+iF
yChjDyyrmiwFupVWQ0Xy2ReFNQiZq7XKVHvsLQe01moSLnxcBxioOPBKt1KkZO7w
Gcbmke0+7AxLaG/F5NPnzRtK1/pRhXQ0XdU8pVh/1/h4GoqRlZ/eN0JDarUhZPkV
kSr96LUYDTxcsAidF7zkzWfmtcJg/Aw8mi14xKVEa6aVyKu54c8kKkdlt0WaigOv
Z/xYhxp24AfoFKaIraDNdsD8q2N7eDYeN4WGLzNSlil+iFjzflI9mq1hTuI/ZNjV
rbvob6FUQ8Cc524gMjbpZCNuZ1gfXzwwhGp0AnQF6CJsWF9uwPpZEVFnnnfiWH3M
oup41EvBhqaAqOlny0sm5pI82nRUCAE3DLkJ1+eAtdQaYblZQkQrRyTuPmJEm+5y
QwdDVw6uHc5OsSj/tyhh8zJ2Xq3zgh3dMONGjJEysxGaCoIb+61PWwMy2dIarVwI
r+c+AY+3PrhgBspNdWZ87JzNHii7ksdjUSVGTTy1vGXgPYrv0lp0IMnKaZP58xiw
rDx7uTlQuPVWNOZvCaT3ZcoxTsNKNscIUe+WJjWx5hdzpv/oksDPY5ltZ0j3hlDS
D+Itk95/cNJVRM/0HpxI1SX9MTZtOSJoEDdUtOpVaOuBAvEK4gvTzdt0r5L+fuI6
o5LAuRo/LO1xVRH49KFRoaznzU3Ch9+kbPb3
-----END CERTIFICATE-----`

// Amazon Root CA 2
var validChain = `-----BEGIN CERTIFICATE-----
MIIHEzCCBPugAwIBAgITBsuooWwIn0Qv1YFdoBwMCACgizANBgkqhkiG9w0BAQwF
ADBGMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2
ZXIgQ0EgMkExDzANBgNVBAMTBkFtYXpvbjAeFw0xODAxMDkwMDA3NTJaFw0xOTAy
MDkwMDA3NTJaMIHaMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwC
AQITCERlbGF3YXJlMR0wGwYDVQQPExRQcml2YXRlIE9yZ2FuaXphdGlvbjEQMA4G
A1UEBRMHNTg0Njc0MzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
EDAOBgNVBAcTB1NlYXR0bGUxHjAcBgNVBAoTFUFtYXpvbiBUcnVzdCBTZXJ2aWNl
czEjMCEGA1UEAxMaZ29vZC5zY2EyYS5hbWF6b250cnVzdC5jb20wggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQCj2I36+u57GVmR1yHkjv4YDUh0/BWrNM9K
cPHUSdXOa+zIDL1fG5LP+OX+ZoP3fSE44ti8xFHDieVk4vvFbI8LGQBAxvyLpQXa
MMiYXyjdDZzNO+CicyYL0fKkIslZxOyhcwRge1Lkyvvi58jlKbEM8Q0vubVpebn5
qCM33ocUEeU0bbYM0XAPoKvKiEkAA5EaW7gt9vuFgz33fFncGaUj9RtuvgcpPPj6
4fb1CVp10Tt3h5UlL3XJBzU2JLgMyJmTkb6y7QsCxgrT3Mo9wOFGG7AZ4dQJVU9x
ns92rTLIBUWLATlaCOXCdf3y25jyXA2asUQnq9Id7i3xkx1NKfh0jtx/vbt+Zn8f
ERC435sjfob+vJ8GF0DVXdn87sG8iP+Sgcbdcl2NXZZJCU6ws2ULtnDwRZkPs23F
LRInlhFgLlf6JwHuDAWf/3LLGpqqpscX7gfKe+D4u4pkvfLUZ9kK8ohcw1QOCtqs
+fmGHdv6bNavkoGVb1UVMoFtiAduk5zPozD8VuPd3e1xBTkl+7dREf0tTp0/W1Fd
Ek/EUS7g64k3cQvNhAoPQzSPHcUzwZN2ARsbj1uTiM0m9c0GGfee4T2TYlAVrAdB
sQDrvQX7GVxPBFFcWpJWV1elpLlf2ZD/Ys9Q/LLQTH+CLGCSnCRKrPGSoSq8NhCX
4wRzf07uHQIDAQABo4IBYzCCAV8wDgYDVR0PAQH/BAQDAgWgMB0GA1UdDgQWBBQy
6xm7ujKybr9hPJuoRyUPoGv9BzAfBgNVHSMEGDAWgBTaQ0rQ/AHAS79YJ4x2zQqB
85Qu9DAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdQYIKwYBBQUHAQEE
aTBnMC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5zY2EyYS5hbWF6b250cnVzdC5j
b20wNgYIKwYBBQUHMAKGKmh0dHA6Ly9jcnQuc2NhMmEuYW1hem9udHJ1c3QuY29t
L3NjYTJhLmNlcjAlBgNVHREEHjAcghpnb29kLnNjYTJhLmFtYXpvbnRydXN0LmNv
bTBQBgNVHSAESTBHMA0GC2CGSAGG/W4BBxgDMDYGBWeBDAEBMC0wKwYIKwYBBQUH
AgEWH2h0dHBzOi8vd3d3LmFtYXpvbnRydXN0LmNvbS9jcHMwDQYJKoZIhvcNAQEM
BQADggIBAAwTlp5GHNy7uU1cbvmSkoCQBAswZNMceRABUu6nen/5v8jRygk+HCYB
5EDkJXv6hVNXPo9jDJd37OZChWMpk58S7hgOYWHtvJfXmaM+U9Aj8cj/T9WtE1EI
t0wNAoDCggsXvYaCtcmp6pUmDZf+Wwz8uw+DV1M37zzJ+Fi9e1W/Y0/AbW3RUjDp
dlNRpaxYqt1uoikDVuXGo3jvjEcedtDoNpk4MtbEmGU7wE+a7FrWLtaOHcZhrCAc
OzGgVIII/wMQLkslNzG6IjmL6pgcAFCP+8EwesGbIhJpgDKv1XKFbyNUIPjyqyaB
/+yadlCjZaVhKrJOcC7ksBJe9q+gNMvtE3dPRS2LMCOuGMHJhdcGLEI2/LsVQ86R
aV0ActKsPkhtuytFfnY6yaIx7C4ENA/CHkhnJ2WZC0IxZYC3r/r0I/nsH6JmmkTB
s/Ky+13f30hwOq4Qey6zy8Io1LnhZ5VexZ9Ltibf9vmibWIm9f2Wz0xCe295WXnO
x+XI9ctgA4PhgivPwmc+U6444U5WpGPQSRBNcjC5oqlTmb6WSN6cGTuwGObWZajj
G9fgBAIPbh1nzojhRnNTpTY97VZjn/sxEPccfprmwxQwIuN4Rlbst+qTRWexGGRu
jWH+XBNeXtvm1ZV/MRc4cFPQGe0ex8tUu1BTk5fqbEgdUeWrZaUs
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGRzCCBC+gAwIBAgITBn+UV1Xxh6kfgWPz5iRiAXf/ODANBgkqhkiG9w0BAQwF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAyMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDJBMQ8wDQYDVQQDEwZBbWF6b24wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQC0P8hSLewmrZ41CCPBQytZs5NBFMq5ztbnMf+kZUp9S25LPfjNW3zgC/6E
qCTWNVMMHhq7ez9IQJk48qbfBTLlZkuKnUWbA9vowrDfcxUN0mRE4B/TJbveXyTf
vE91iDlqDrERecE9D8sdjzURrtHTp27lZdRkXFvfEVCq4hl3sHkzjodisaQthLp1
gLsiA7vKt+8zcL4Aeq52UyYb8r4/jdZ3KaQp8O/T4VwDCRKm8ey3kttpJWaflci7
eRzNjY7gE3NMANVXCeQwOBfH2GjINFCObmPsqiBuoAnsv2k5aQLNoU1OZk08ClXm
mEZ2rI5qZUTX1HuefBJnpMkPugFCw8afaHnB13SkLE7wxX8SZRdDIe5WiwyDL1tR
2+8lpz4JsMoFopHmD3GaHyjbN+hkOqHgLltwewOsiyM0u3CZphypN2KeD+1FLjnY
TgdIAd1FRgK2ZXDDrEdjnsSEfShKf0l4mFPSBs9E3U6sLmubDRXKLLLpa/dF4eKu
LEKS1bXYT28iM6D5gSCnzho5G4d18jQD/slmc5XmRo5Pig0RyBwDaLuxeIZuiJ0A
J6YFhffbrLYF5dEQl0cU+t3VBK5u/o1WkWXsZawU038lWn/AXerodT/pAcrtWA4E
NQEN09WEKMhZVPhqdwhF/Gusr04mQtKt7T2v6UMQvtVglv5E7wIDAQABo4IBOTCC
ATUwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYE
FNpDStD8AcBLv1gnjHbNCoHzlC70MB8GA1UdIwQYMBaAFLAM8Eww9AVYAkj9M+VS
r0uE42ZSMHsGCCsGAQUFBwEBBG8wbTAvBggrBgEFBQcwAYYjaHR0cDovL29jc3Au
cm9vdGNhMi5hbWF6b250cnVzdC5jb20wOgYIKwYBBQUHMAKGLmh0dHA6Ly9jcnQu
cm9vdGNhMi5hbWF6b250cnVzdC5jb20vcm9vdGNhMi5jZXIwPwYDVR0fBDgwNjA0
oDKgMIYuaHR0cDovL2NybC5yb290Y2EyLmFtYXpvbnRydXN0LmNvbS9yb290Y2Ey
LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBAEO5W+iF
yChjDyyrmiwFupVWQ0Xy2ReFNQiZq7XKVHvsLQe01moSLnxcBxioOPBKt1KkZO7w
Gcbmke0+7AxLaG/F5NPnzRtK1/pRhXQ0XdU8pVh/1/h4GoqRlZ/eN0JDarUhZPkV
kSr96LUYDTxcsAidF7zkzWfmtcJg/Aw8mi14xKVEa6aVyKu54c8kKkdlt0WaigOv
Z/xYhxp24AfoFKaIraDNdsD8q2N7eDYeN4WGLzNSlil+iFjzflI9mq1hTuI/ZNjV
rbvob6FUQ8Cc524gMjbpZCNuZ1gfXzwwhGp0AnQF6CJsWF9uwPpZEVFnnnfiWH3M
oup41EvBhqaAqOlny0sm5pI82nRUCAE3DLkJ1+eAtdQaYblZQkQrRyTuPmJEm+5y
QwdDVw6uHc5OsSj/tyhh8zJ2Xq3zgh3dMONGjJEysxGaCoIb+61PWwMy2dIarVwI
r+c+AY+3PrhgBspNdWZ87JzNHii7ksdjUSVGTTy1vGXgPYrv0lp0IMnKaZP58xiw
rDx7uTlQuPVWNOZvCaT3ZcoxTsNKNscIUe+WJjWx5hdzpv/oksDPY5ltZ0j3hlDS
D+Itk95/cNJVRM/0HpxI1SX9MTZtOSJoEDdUtOpVaOuBAvEK4gvTzdt0r5L+fuI6
o5LAuRo/LO1xVRH49KFRoaznzU3Ch9+kbPb3
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFQTCCAymgAwIBAgITBmyf0pY1hp8KD+WGePhbJruKNzANBgkqhkiG9w0BAQwF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAyMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK2Wny2cSkxK
gXlRmeyKy2tgURO8TW0G/LAIjd0ZEGrHJgw12MBvIITplLGbhQPDW9tK6Mj4kHbZ
W0/jTOgGNk3Mmqw9DJArktQGGWCsN0R5hYGCrVo34A3MnaZMUnbqQ523BNFQ9lXg
1dKmSYXpN+nKfq5clU1Imj+uIFptiJXZNLhSGkOQsL9sBbm2eLfq0OQ6PBJTYv9K
8nu+NQWpEjTj82R0Yiw9AElaKP4yRLuH3WUnAnE72kr3H9rN9yFVkE8P7K6C4Z9r
2UXTu/Bfh+08LDmG2j/e7HJV63mjrdvdfLC6HM783k81ds8P+HgfajZRRidhW+me
z/CiVX18JYpvL7TFz4QuK/0NURBs+18bvBt+xa47mAExkv8LV/SasrlX6avvDXbR
8O70zoan4G7ptGmh32n2M8ZpLpcTnqWHsFcQgTfJU7O7f/aS0ZzQGPSSbtqDT6Zj
mUyl+17vIWR6IF9sZIUVyzfpYgwLKhbcAS4y2j5L9Z469hdAlO+ekQiG+r5jqFoz
7Mt0Q5X5bGlSNscpb/xVA1wf+5+9R+vnSUeVC06JIglJ4PVhHvG/LopyboBZ/1c6
+XUyo05f7O0oYtlNc/LMgRdg7c3r3NunysV+Ar3yVAhU/bQtCSwXVEqY0VThUWcI
0u1ufm8/0i2BWSlmy5A5lREedCf+3euvAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMB
Af8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSwDPBMMPQFWAJI/TPlUq9LhONm
UjANBgkqhkiG9w0BAQwFAAOCAgEAqqiAjw54o+Ci1M3m9Zh6O+oAA7CXDpO8Wqj2
LIxyh6mx/H9z/WNxeKWHWc8w4Q0QshNabYL1auaAn6AFC2jkR2vHat+2/XcycuUY
+gn0oJMsXdKMdYV2ZZAMA3m3MSNjrXiDCYZohMr/+c8mmpJ5581LxedhpxfL86kS
k5Nrp+gvU5LEYFiwzAJRGFuFjWJZY7attN6a+yb3ACfAXVU3dJnJUH/jWS5E4ywl
7uxMMne0nxrpS10gxdr9HIcWxkPo1LsmmkVwXqkLN1PiRnsn/eBG8om3zEK2yygm
btmlyTrIQRNg91CMFa6ybRoVGld45pIq2WWQgj9sAq+uEjonljYE1x2igGOpm/Hl
urR8FLBOybEfdF849lHqm/osohHUqS0nGkWxr7JOcQ3AWEbWaQbLU8uz/mtBzUF+
fUwPfHJ5elnNXkoOrJupmHN5fLT0zLm4BwyydFy4x2+IoZCn9Kr5v2c69BoVYh63
n749sSmvZ6ES8lgQGVMDMBu4Gon2nL2XA46jCfMdiyHxtN/kHNGfZQIG6lzWE7OE
76KlXIx3KadowGuuQNKotOrN8I1LOJwZmhsoVLiJkO/KdYE+HvJkJMcYr07/R54H
9jVlpNMKVv/1F2Rs76giJUmTtt8AF9pYfl3uxRuw0dFfIRDH+fO6AgonB8Xx1sfT
4PsJYGw=
-----END CERTIFICATE-----`

func TestValidChain(t *testing.T) {
	chain := parseChain(validChain)
	c, err := certutil.NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Delete()
	statuses, err := VerifyChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != len(chain) {
		t.Fatalf("wanted %d expiration statues, got %d\n", len(chain), len(statuses))
	}
	for _, status := range statuses {
		if status.Status != Valid {
			t.Fail()
			t.Errorf("wanted the leaf to be unexpired, valid, and with a know issuer, got %v", status)
		}
	}
}

func TestValidMissingRoot(t *testing.T) {
	chain := parseChain(validChain)
	c, err := certutil.NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Delete()
	statuses, err := VerifyChain(chain[:2])
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range statuses {
		if status.Status != IssuerUnknown {
			t.Fail()
			t.Errorf("wanted the leaf to be unexpired, invalid, and with an UNKNOWN issuer, got %v", status)
		}
	}
}

func TestValidMissingIntermediate(t *testing.T) {
	chain := parseChain(validChain)
	c, err := certutil.NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Delete()
	statuses, err := VerifyChain([]*x509.Certificate{chain[0], chain[2]})
	if err != nil {
		t.Fatal(err)
	}
	leaf := statuses[0]
	root := statuses[1]
	if leaf.Status != IssuerUnknown {
		t.Fail()
		t.Errorf("wanted the leaf to be unexpired, invalid, and with an UNKNOWN issuer, got %v", leaf)
	}
	if root.Status != Valid {
		t.Fail()
		t.Errorf("wanted the leaf to be unexpired, valid, and with a know issuer, got %v", root)
	}
}

func TestExpiredChain(t *testing.T) {
	chain := parseChain(expiredChain)
	c, err := certutil.NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Delete()
	statuses, err := VerifyChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != len(chain) {
		t.Fatalf("wanted %d expiration statues, got %d\n", len(chain), len(statuses))
	}
	for _, status := range statuses[:2] {
		if status.Status != Expired {
			t.Fail()
			t.Errorf("wanted the leaf to be expired, valid, and with a know issuer, got %v", status)
		}
	}
	root := statuses[2]
	if root.Status != Valid {
		t.Fail()
		t.Errorf("wanted the leaf to be unexpired, valid, and with a know issuer, got %v", root)
	}
}

func TestExpiredMissingRoot(t *testing.T) {
	chain := parseChain(expiredChain)
	c, err := certutil.NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Delete()
	statuses, err := VerifyChain(chain[:2])
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range statuses {
		if status.Status != Expired {
			t.Fail()
			t.Errorf("wanted the cert to be unexpired, invalid, and with an UNKNOWN issuer, got %v", status)
		}
	}
}

func TestExpiredMissingIntermediate(t *testing.T) {
	chain := parseChain(expiredChain)
	c, err := certutil.NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Delete()
	statuses, err := VerifyChain([]*x509.Certificate{chain[0], chain[2]})
	if err != nil {
		t.Fatal(err)
	}
	leaf := statuses[0]
	root := statuses[1]
	if leaf.Status != Expired {
		t.Fail()
		t.Errorf("wanted the leaf to be expired, invalid, and with an UNKNOWN issuer, got %v", leaf)
	}
	if root.Status != Valid {
		t.Fail()
		t.Errorf("wanted the leaf to be unexpired, valid, and with a know issuer, got %v", root)
	}
}
