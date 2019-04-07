/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ocsp

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/mozilla/capi/lib/certificateUtils"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"testing"
)

var AmazonRootCA1 = `-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy
rqXRfboQnoZsG4q5WTP468SQvvG5
-----END CERTIFICATE-----`

var AmazonRootCA1Valid = `-----BEGIN CERTIFICATE-----
MIIFEjCCA/qgAwIBAgITBvHXFfllHZXWP8myqI3v5T1QCDANBgkqhkiG9w0BAQsF
ADBGMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2
ZXIgQ0EgMUExDzANBgNVBAMTBkFtYXpvbjAeFw0xOTAxMjgyMzEzMzlaFw0yMDAy
MjgyMzEzMzlaMIHZMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwC
AQITCERlbGF3YXJlMRwwGgYDVQQPExNQcml2YXRlT3JnYW5pemF0aW9uMRAwDgYD
VQQFEwc1ODQ2NzQzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
MA4GA1UEBxMHU2VhdHRsZTEeMBwGA1UEChMVQW1hem9uIFRydXN0IFNlcnZpY2Vz
MSMwIQYDVQQDExpnb29kLnNjYTFhLmFtYXpvbnRydXN0LmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBANvKSz8Hs5lfb80BC6B1ReHEUsAqE4lHy9sd
T6J7TRUkzukhyJmQ+tPS3wD67FSmVeaiSqsqVrJSZocBRtO3KORgAeXjehZ4q2XR
8VxWqU5QS85QT0dWLOf8DiPESHCPjSVEUh58vZ59k2nY2dYjQUz+KYZCci1tE2MU
KlZbtI7YozLkzmaNHkGUDkJqz6KM7YR58Q2+mD/sTg35/lq/0hiXEiNMkdHxZNDt
eM3qUakcu3wxcwC7A3gLfvpWEgnnrIJMQK3iKq6rp81sN0zHHoYkHQ5INRRQ5Kcw
p3HORmXNCLszfvesa2jhrxbGpl5jfVvwD8+if7yTY4YjpwCPHSUCAwEAAaOCAWMw
ggFfMA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQUVYiPMfFU3kEvv7x7THysxbc4
MPwwHwYDVR0jBBgwFoAUYtRCXoZwdWqQvMa40k1gwjS6UTowHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYh
aHR0cDovL29jc3Auc2NhMWEuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipo
dHRwOi8vY3J0LnNjYTFhLmFtYXpvbnRydXN0LmNvbS9zY2ExYS5jZXIwJQYDVR0R
BB4wHIIaZ29vZC5zY2ExYS5hbWF6b250cnVzdC5jb20wUAYDVR0gBEkwRzANBgtg
hkgBhv1uAQcYAzA2BgVngQwBATAtMCsGCCsGAQUFBwIBFh9odHRwczovL3d3dy5h
bWF6b250cnVzdC5jb20vY3BzMA0GCSqGSIb3DQEBCwUAA4IBAQCJZwyxhTd2LKiB
tU1V7MgmOlMT0CzPE4UBRNvwg6FSwhs+l+9PsmRp7NjojK9JrdmKTvMLS8F8N6aX
tp1+kmuipp3j5sLSxN7fsSHL4wXiAcJ1HtUqXZXI3AIUic7DgDCALO/eiwEw8or7
Fd7vBe5KxoOuPbvOnWrvekVWmKBz77i9Tc82NszHmSt2l0cVonVKV/lu72gudm1s
Al7YvDMhiVzz2QrrIaJlN8j5ZvLXzstZ/3qq6Eo/vpweQig4/fdNkp1FBgJ2wvev
C7Y0PtfZJs2mIf9nlVhHIkCKx6uxfIVuh6WCqBznNBItOZdJIna2avmnDt4H6Lw5
i31KU3gP
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIERzCCAy+gAwIBAgITBn+UV1CMZIwJymUucXkYMOclkjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCeQM3XCsIZunv8bSJxOqkc/ed87uL76FDB7teBNThDRB+1J7aITuadbNfH
5ZfZykrdZ1qQLKxP6DwHOmJr9u2b4IxjUX9qUMuq4B02ghD2g6yU3YivEosZ7fpo
srD2TBN29JpgPGrOrpOE+ArZuIpBjdKFinemu6fTDD0NCeQlfyHXd1NOYyfYRLTa
xlpDqr/2M41BgSkWQfSPHHyRWNQgWBiGsIQaS8TK0g8OWi1ov78+2K9DWT+AHgXW
AanjZK91GfygPXJYSlAGxSiBAwH/KhAMifhaoFYAbH0Yuohmd85B45G2xVsop4TM
Dsl007U7qnS7sdJ4jYGzEvva/a95AgMBAAGjggE5MIIBNTASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUYtRCXoZwdWqQvMa40k1g
wjS6UTowHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBEGA1UdIAQKMAgw
BgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAMHbSWHRFMzGNIE0qhN6gnRahTrTU
CDPwe7l9/q0IA+QBlrpUHnlAreetYeH1jB8uF3qXXzy22gpBU7NqulTkqSPByT1J
xOhpT2FpO5R3VAdMPdWfSEgtrED0jkmyUQrR1T+/A+nBLdJZeQcl+OqLgeY790JM
JJTsJnnI6FBWeTGhcDI4Y+n3KS3QCVePeWI7jx1dhrHcXH+QDX8Ywe31hV7YENdr
HDpUXrjK6eHN8gazy8G6pndXHFwHp4auiZbJbYAk/q1peOTRagD2JojcLkm+i3cD
843t4By6YT/PVlePU2PCWejkrJQnKQAPOov7IA8kuO2RDWuzE/zF6Hotdg==
-----END CERTIFICATE-----
` + AmazonRootCA1

var AmazonRootCA1Expired = `-----BEGIN CERTIFICATE-----
MIIEJjCCAw6gAwIBAgITBn+UamNhIrAVNS+GbA2DjtIeyDANBgkqhkiG9w0BAQsF
ADBGMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2
ZXIgQ0EgMUExDzANBgNVBAMTBkFtYXpvbjAeFw0xNTEyMDMyMjM5MDZaFw0xNTEy
MDYwMDAwMDBaMCgxJjAkBgNVBAMTHWV4cGlyZWQuc2NhMWEuYW1hem9udHJ1c3Qu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv56LNAcn9gwjqR25
Jtw2D9l4T77nXlKCG5AqjDun1qtrifJZBn3YVh9UUOqwtW6BjXGzsCICWIhv92g5
OrzsRsKdwK/Ad35X5CkcGR6tAXJSOL7QosJ7BZnbSPfkqQLqgtttx9N+g+LuAVYb
/TKzJoWhGyJas5N7PufMc1Dy8tCA7TvbCDF6AEYN74rTBSv9iVxfwwT+YUERhZhk
7jUqNkJg5LfyB1aT7zK1xx8UMkeQY/KtAS6YxqjNCvmyPSGZHDE4MujnkCngWSmm
rOg/y1uU9gsX6BteHHyTc0CccO06Pm0qkB5qcoNj2EeF5HdLKXQeJQ4uYD1hmKvg
vYeLsQIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdDgQWBBTHWTL1
sJbjN8v7LJwyNU64kzsc/TAfBgNVHSMEGDAWgBRi1EJehnB1apC8xrjSTWDCNLpR
OjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdQYIKwYBBQUHAQEEaTBn
MC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5zY2ExYS5hbWF6b250cnVzdC5jb20w
NgYIKwYBBQUHMAKGKmh0dHA6Ly9jcnQuc2NhMWEuYW1hem9udHJ1c3QuY29tL3Nj
YTFhLmNlcjAoBgNVHREEITAfgh1leHBpcmVkLnNjYTFhLmFtYXpvbnRydXN0LmNv
bTATBgNVHSAEDDAKMAgGBmeBDAECATANBgkqhkiG9w0BAQsFAAOCAQEAiWkrVciR
+Pz5FzVpjeHHqn5XtvS8p0uwSP3C6P8Q8TmPkIiX1hPbN2Xv0h01On+cRyMPjl6a
k/qymZxBX+0JWBBAwnxJHh0v76gIs9IMB95qaDgfq4rdTpItIxh28WKXJyD+KnUg
gYyUorHNOUsbM3Af00BgBf6/xsiCN0DEgKhcfurpK/tCxWj1/Hbcxv7T68ClGtnY
QU+n7nO8Sa1sJJsEOZdAQfVNhJYTVoNxW7QetZ+vWHpSotVpKkr4MKKgIOMOBq9l
/QDfLsmOWFVkjn8m/DkLs+WfCD0sSUbBN4eIVioBcZHucr7BCnJiBjObkwF6IEe2
3cZz3/sPAXlF2g==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIERzCCAy+gAwIBAgITBn+UV1CMZIwJymUucXkYMOclkjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCeQM3XCsIZunv8bSJxOqkc/ed87uL76FDB7teBNThDRB+1J7aITuadbNfH
5ZfZykrdZ1qQLKxP6DwHOmJr9u2b4IxjUX9qUMuq4B02ghD2g6yU3YivEosZ7fpo
srD2TBN29JpgPGrOrpOE+ArZuIpBjdKFinemu6fTDD0NCeQlfyHXd1NOYyfYRLTa
xlpDqr/2M41BgSkWQfSPHHyRWNQgWBiGsIQaS8TK0g8OWi1ov78+2K9DWT+AHgXW
AanjZK91GfygPXJYSlAGxSiBAwH/KhAMifhaoFYAbH0Yuohmd85B45G2xVsop4TM
Dsl007U7qnS7sdJ4jYGzEvva/a95AgMBAAGjggE5MIIBNTASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUYtRCXoZwdWqQvMa40k1g
wjS6UTowHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBEGA1UdIAQKMAgw
BgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAMHbSWHRFMzGNIE0qhN6gnRahTrTU
CDPwe7l9/q0IA+QBlrpUHnlAreetYeH1jB8uF3qXXzy22gpBU7NqulTkqSPByT1J
xOhpT2FpO5R3VAdMPdWfSEgtrED0jkmyUQrR1T+/A+nBLdJZeQcl+OqLgeY790JM
JJTsJnnI6FBWeTGhcDI4Y+n3KS3QCVePeWI7jx1dhrHcXH+QDX8Ywe31hV7YENdr
HDpUXrjK6eHN8gazy8G6pndXHFwHp4auiZbJbYAk/q1peOTRagD2JojcLkm+i3cD
843t4By6YT/PVlePU2PCWejkrJQnKQAPOov7IA8kuO2RDWuzE/zF6Hotdg==
-----END CERTIFICATE-----
` + AmazonRootCA1

var AmazonRootCA1Revoked = `-----BEGIN CERTIFICATE-----
MIIE2zCCA8OgAwIBAgITBvHXdK1ee20lHSF2YXgrvbbzfTANBgkqhkiG9w0BAQsF
ADBGMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2
ZXIgQ0EgMUExDzANBgNVBAMTBkFtYXpvbjAeFw0xOTAxMjgyMzM0MzhaFw0yMjA0
MjgyMzM0MzhaMIHcMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwC
AQITCERlbGF3YXJlMRwwGgYDVQQPExNQcml2YXRlT3JnYW5pemF0aW9uMRAwDgYD
VQQFEwc1ODQ2NzQzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
MA4GA1UEBxMHU2VhdHRsZTEeMBwGA1UEChMVQW1hem9uIFRydXN0IFNlcnZpY2Vz
MSYwJAYDVQQDEx1yZXZva2VkLnNjYTFhLmFtYXpvbnRydXN0LmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANUoHop9sW+QlgVsdtacioraTAWHcSTd
MNkOkOEMgJIFPyfdcDvW/H2NvpdYeIQqzaCgT2kcsONWTZTPJMirCPnzl1ohHOZU
uTnOVkamGxvNmQCURLBXmlCMRTCI5RY3CuYntFFbSPAnbumsF+K/gKqcE6ME53Bw
PAwn4qwavB0i5Ib7Jk8XYzxSYXC9l8QLxt6fshPJRlecpXzfmVFvMAm3IbaLcpuv
AtD+8I2KwjNtBPRPNYeFsWxwsgUGAyHEGa61oTGUqqAXu5YmPfyK+YTOJdoofsh4
Tf3K7AKxnPWuvY3RNTs1pzEVwJYZqSsNwbgyKJJ4+0Xe4iP7qB8SYf8CAwEAAaOC
ASkwggElMA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQUGHreoz+LP/Wr+RKzuexO
V8ICtmEwHwYDVR0jBBgwFoAUYtRCXoZwdWqQvMa40k1gwjS6UTowHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcw
AYYhaHR0cDovL29jc3Auc2NhMWEuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAC
hipodHRwOi8vY3J0LnNjYTFhLmFtYXpvbnRydXN0LmNvbS9zY2ExYS5jZXIwKAYD
VR0RBCEwH4IdcmV2b2tlZC5zY2ExYS5hbWF6b250cnVzdC5jb20wEwYDVR0gBAww
CjAIBgZngQwBAgEwDQYJKoZIhvcNAQELBQADggEBABSbe1UCLL7Qay6XK5wD8B5a
wvR1XG3UrggpVIz/w5cutEm/yE71hzE0gag/3YPbNYEnaLbJH+9jz4YW9wd/cEPj
xSK5PErAQjCd+aA4LKN1xqkSysgYknl0y47hJBXGnWf+hxvBBHeSoUzM0KIC21pC
ZyXrmfaPCQAz13ruYIYdQaETqXGVORmKbf/a+Zn18/tfQt0LeeCYVoSopbXWQvcJ
gUMtdIqYQmb8aVj0pdZXwKl4yZ2DtlS3Z9MpWNgQNlhRPmiYlu28y2yTtZ9SwD6m
2f+cwc19aJrDT4Y280px+jRU7dIE6oZVJU+yBRVIZYpUFAB7extCMVxnTkCf8Dk=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIERzCCAy+gAwIBAgITBn+UV1CMZIwJymUucXkYMOclkjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCeQM3XCsIZunv8bSJxOqkc/ed87uL76FDB7teBNThDRB+1J7aITuadbNfH
5ZfZykrdZ1qQLKxP6DwHOmJr9u2b4IxjUX9qUMuq4B02ghD2g6yU3YivEosZ7fpo
srD2TBN29JpgPGrOrpOE+ArZuIpBjdKFinemu6fTDD0NCeQlfyHXd1NOYyfYRLTa
xlpDqr/2M41BgSkWQfSPHHyRWNQgWBiGsIQaS8TK0g8OWi1ov78+2K9DWT+AHgXW
AanjZK91GfygPXJYSlAGxSiBAwH/KhAMifhaoFYAbH0Yuohmd85B45G2xVsop4TM
Dsl007U7qnS7sdJ4jYGzEvva/a95AgMBAAGjggE5MIIBNTASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUYtRCXoZwdWqQvMa40k1g
wjS6UTowHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBEGA1UdIAQKMAgw
BgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAMHbSWHRFMzGNIE0qhN6gnRahTrTU
CDPwe7l9/q0IA+QBlrpUHnlAreetYeH1jB8uF3qXXzy22gpBU7NqulTkqSPByT1J
xOhpT2FpO5R3VAdMPdWfSEgtrED0jkmyUQrR1T+/A+nBLdJZeQcl+OqLgeY790JM
JJTsJnnI6FBWeTGhcDI4Y+n3KS3QCVePeWI7jx1dhrHcXH+QDX8Ywe31hV7YENdr
HDpUXrjK6eHN8gazy8G6pndXHFwHp4auiZbJbYAk/q1peOTRagD2JojcLkm+i3cD
843t4By6YT/PVlePU2PCWejkrJQnKQAPOov7IA8kuO2RDWuzE/zF6Hotdg==
-----END CERTIFICATE-----` + AmazonRootCA1

func TestRevoked(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1Revoked))
	if err != nil {
		t.Fatal(err)
	}
	leaf := queryOCSP(chain[0], chain[1])
	for _, responder := range leaf {
		if responder.Status != Revoked {
			t.Errorf("wanted revoked, got %v from %s", responder.Status, responder.Responder)
		}
	}
	intermediate := queryOCSP(chain[1], chain[2])
	for _, responder := range intermediate {
		if responder.Status != Good {
			t.Errorf("wanted good, got %v from %s", responder.Status, responder.Responder)
		}
	}
	root := queryOCSP(chain[2], chain[2])
	for _, responder := range root {
		if responder.Status != Good {
			t.Errorf("wanted good, got %v from %s", responder.Status, responder.Responder)
		}
	}
}

func TestGood(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1Valid))
	if err != nil {
		t.Fatal(err)
	}
	leaf := queryOCSP(chain[0], chain[1])
	for _, responder := range leaf {
		if responder.Status != Good {
			t.Errorf("wanted good, got %v from %s", responder.Status, responder.Responder)
		}
	}
	intermediate := queryOCSP(chain[1], chain[2])
	for _, responder := range intermediate {
		if responder.Status != Good {
			t.Errorf("wanted good, got %v from %s", responder.Status, responder.Responder)
		}
	}
	root := queryOCSP(chain[2], chain[2])
	for _, responder := range root {
		if responder.Status != Good {
			t.Errorf("wanted good, got %v from %s", responder.Status, responder.Responder)
		}
	}
}

func TestExpired(t *testing.T) {
	chain, err := certificateUtils.ParseChain([]byte(AmazonRootCA1Expired))
	if err != nil {
		t.Fatal(err)
	}
	leaf := queryOCSP(chain[0], chain[1])
	for _, responder := range leaf {
		if responder.Status != Good {
			t.Errorf("wanted good, got %v from %s", responder.Status, responder.Responder)
		}
	}
	intermediate := queryOCSP(chain[1], chain[2])
	for _, responder := range intermediate {
		if responder.Status != Good {
			t.Errorf("wanted good, got %v from %s", responder.Status, responder.Responder)
		}
	}
	root := queryOCSP(chain[2], chain[2])
	for _, responder := range root {
		if responder.Status != Good {
			t.Errorf("wanted good, got %v from %s", responder.Status, responder.Responder)
		}
	}
}

func TestMarshaling(t *testing.T) {
	var o OCSP
	o.Status = Good
	_, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	o.Status = Revoked
	_, err = json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	o.Status = Unknown
	_, err = json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnmarshaling(t *testing.T) {
	var o OCSP
	o.Status = Good
	s, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var r OCSP
	err = json.Unmarshal(s, &r)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != Good {
		t.Errorf("expected Good, got %v", r.Status)
	}

	o.Status = Revoked
	r = OCSP{}
	s, err = json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(s, &r)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != Revoked {
		t.Errorf("expected Revoked, got %v", r.Status)
	}

	o.Status = Unknown
	s, err = json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(s, &r)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != Unknown {
		t.Errorf("expected Unknown, got %v", r.Status)
	}
}

func TestUnauthorized(t *testing.T) {
	subject := "https://revoked.identrustssl.com/"
	chain, err := certificateUtils.GatherCertificateChain(subject)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(chain)
	resp := VerifyChain(chain)
	for _, i := range resp {
		for _, j := range i {
			t.Log(j.Error)
		}
	}
}

const badASN1URL = `https://global-root-ca-expired.chain-demos.digicert.com/`

func TestBadASN1(t *testing.T) {
	chain, err := certificateUtils.GatherCertificateChain(badASN1URL)
	if err != nil {
		t.Fatal(err)
	}
	s := bytes.NewBuffer([]byte{})
	pem.Encode(s, &pem.Block{"CERTIFICATE", nil, chain[0].Raw})
	t.Log(s.String())
	b := responseAsBytes(chain[0], chain[1], chain[0].OCSPServer[0])
	t.Log(chain[0].OCSPServer[0])
	t.Log(string(b))
}

func responseAsBytes(certificate, issuer *x509.Certificate, responder string) []byte {
	req, err := ocsp.CreateRequest(certificate, issuer, nil)
	if err != nil {
		panic(err)
	}
	r, err := http.NewRequest("POST", responder, bytes.NewReader(req))
	if err != nil {
		panic(err)
	}
	r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0")
	r.Header.Set("Content-Type", OCSPContentType)
	ret, err := http.DefaultClient.Do(r)
	if err != nil {
		panic(err)
	}
	defer ret.Body.Close()
	httpResp, err := ioutil.ReadAll(ret.Body)
	if err != nil {
		panic(err)
	}
	return httpResp
}

var ffffff = []byte(`-----BEGIN CERTIFICATE----- 
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ 
RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD 
VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX 
DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y 
ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy 
VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr 
mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr 
IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK 
mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu 
XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy 
dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye 
jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1 
BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3 
DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92 
9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx 
jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0 
Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz 
ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS 
R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp 
-----END CERTIFICATE-----`)

func TestOneThing(t *testing.T) {
	subject := "https://global-root-ca-expired.chain-demos.digicert.com/"
	b, _ := pem.Decode(ffffff)
	root, _ := x509.ParseCertificate(b.Bytes)
	chain, _ := certificateUtils.GatherCertificateChain(subject)
	chain = certificateUtils.EmplaceRoot(chain, root)
	t.Log(VerifyChain(chain))
}
