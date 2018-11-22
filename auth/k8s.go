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
	"time"

	"github.com/spf13/viper"
)

func CreateCert() error {

	viper.SetDefault("ssl.dir", "ssl")

	viper.SetDefault("ssl.cert.ca", CertConfig{
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
	})

	viper.SetDefault("ssl.cert.apiserver", CertConfig{
		Organization:       "kubernetes",
		OrganizationalUnit: "kubernetes Security",
		Locality:           "Beijing",
		Province:           "Beijing",
		Country:            "CN",
		StreetAddress:      "Beijing",
		CommonName:         "kube-apiserver",
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
	})

	viper.SetDefault("ssl.cert.proxy", CertConfig{
		Organization:       "kubernetes",
		OrganizationalUnit: "kubernetes Security",
		Locality:           "Beijing",
		Province:           "Beijing",
		Country:            "CN",
		StreetAddress:      "Beijing",
		CommonName:         "kube-proxy",
		PrivateKeyBits:     4096,
		ValidityPeriod:     86700 * time.Hour,
		SignatureAlgorithm: x509.SHA512WithRSA,
	})

	viper.SetDefault("ssl.cert.admin", CertConfig{
		Organization:       "kubernetes",
		OrganizationalUnit: "kubernetes Security",
		Locality:           "Beijing",
		Province:           "Beijing",
		Country:            "CN",
		StreetAddress:      "Beijing",
		CommonName:         "kubernetes admin",
		PrivateKeyBits:     4096,
		ValidityPeriod:     86700 * time.Hour,
		SignatureAlgorithm: x509.SHA512WithRSA,
	})

	sslDir := viper.GetString("ssl.dir")

	var caCfg, apiserverCfg, proxyCfg, adminCfg CertConfig
	err := viper.UnmarshalKey("ssl.cert.ca", &caCfg)
	if err != nil {
		return err
	}
	err = viper.UnmarshalKey("ssl.cert.apiserver", &apiserverCfg)
	if err != nil {
		return err
	}
	err = viper.UnmarshalKey("ssl.cert.proxy", &proxyCfg)
	if err != nil {
		return err
	}
	err = viper.UnmarshalKey("ssl.cert.admin", &adminCfg)
	if err != nil {
		return err
	}

	// generate CA
	caCert, err := caCfg.GenerateRootCert()
	if err != nil {
		return err
	}
	err = caCert.Save(sslDir, "kubernetes-root-ca")
	if err != nil {
		return err
	}

	// generate apiserver cert
	apiserverCert, err := apiserverCfg.GenerateCert(caCert)
	if err != nil {
		return err
	}
	err = apiserverCert.Save(sslDir, "kube-apiserver")
	if err != nil {
		return err
	}

	// generate proxy cert
	proxyCert, err := proxyCfg.GenerateCert(caCert)
	if err != nil {
		return err
	}
	err = proxyCert.Save(sslDir, "kube-proxy")
	if err != nil {
		return err
	}

	// generate admin cert
	adminCert, err := adminCfg.GenerateCert(caCert)
	if err != nil {
		return err
	}
	err = adminCert.Save(sslDir, "kube-admin")
	if err != nil {
		return err
	}

	return nil

}
