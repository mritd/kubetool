/*
 * Copyright 2018 mritd <mritd1234@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package auth

import (
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestCert_GenerateRootCert(t *testing.T) {
	config := CertConfig{
		Organization:       "kubernetes",
		OrganizationalUnit: "kubernetes Security",
		Locality:           "Beijing",
		Province:           "Beijing",
		Country:            "CN",
		StreetAddress:      "Beijing",
		CommonName:         "kubernetes root ca",
		PrivateKeyBits:     4096,
		ValidityPeriod:     86700 * time.Hour,
		SignatureAlgorithm: x509.SHA512WithRSA,
	}

	cert, err := config.GenerateRootCert()
	if err != nil {
		t.Fatal(err)
	}
	err = cert.Save(".", "kubernetes-root-ca")
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertConfig_GenerateCert(t *testing.T) {

	cert, err := CertLoad("kubernetes-root-ca.pem", "kubernetes-root-ca-key.pem")
	if err != nil {
		t.Fatal(err)
	}

	config := CertConfig{
		Organization:       "kubernetes",
		OrganizationalUnit: "kubernetes Security",
		Locality:           "Beijing",
		Province:           "Beijing",
		Country:            "CN",
		StreetAddress:      "Beijing",
		CommonName:         "kubernetes master",
		PrivateKeyBits:     2048,
		ValidityPeriod:     86700 * time.Hour,
		SignatureAlgorithm: x509.SHA512WithRSA,
		DNSNames: []string{
			"master1.kubernetes.node",
			"master2.kubernetes.node",
			"master3.kubernetes.node",
		},
		IPAddresses: []net.IP{
			net.ParseIP("192.168.1.11"),
			net.ParseIP("192.168.1.12"),
			net.ParseIP("192.168.1.13"),
		},
	}

	newCert, err := config.GenerateCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	err = newCert.Save(".", "kubernetes-master")
	if err != nil {
		t.Fatal(err)
	}

	err = newCert.Cert.CheckSignatureFrom(cert.Cert)
	if err != nil {
		t.Fatal(err)
	}
}
