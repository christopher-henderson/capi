/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

 package ocsp

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"
)

func parseChain(path string) (certs []*x509.Certificate) {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	raw, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	for _, b := range bytes.SplitAfter(raw, []byte("-----END CERTIFICATE-----")) {
		block, rest := pem.Decode(b)
		if len(rest) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
		certs = append(certs, cert)
	}
	return
}

var revoked = `/Users/chris/Documents/Contracting/mozilla/CACop/src/testdata/data/AffirmTrust Premium/revoked`

func TestOCSP(t *testing.T) {
	chain := parseChain(revoked)
	for i, cert := range chain[:len(chain)-1] {
		t.Log(queryOCSP(cert, chain[i+1]))
	}
}
