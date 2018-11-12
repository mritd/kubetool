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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type CertConfig struct {
	Organization       string
	OrganizationalUnit string
	Locality           string
	Province           string
	StreetAddress      string
	Country            string
	CommonName         string
	ValidityPeriod     time.Duration
	PrivateKeyBits     int
	SignatureAlgorithm x509.SignatureAlgorithm
	IPAddresses        []net.IP
	DNSNames           []string
}

type CertInfo struct {
	Cert        *x509.Certificate
	certDERData []byte
	PrivateKey  *rsa.PrivateKey
}

func (ci *CertInfo) Save(dir, prefix string) error {
	info, err := os.Stat(dir)
	if err != nil {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
	} else if !info.IsDir() {
		return fmt.Errorf("%s is not dir", dir)
	}

	certFile, err := os.Create(filepath.Join(dir, prefix+".pem"))
	if err != nil {
		return fmt.Errorf("failed to create cert file: %v", err)
	}
	defer certFile.Close()
	privateKeyFile, err := os.Create(filepath.Join(dir, prefix+"-key.pem"))
	if err != nil {
		return fmt.Errorf("failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: ci.certDERData})
	if err != nil {
		return fmt.Errorf("failed to save cert: %v", err)
	}
	err = pem.Encode(privateKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ci.PrivateKey)})
	if err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}
	return nil
}

func (c *CertConfig) GenerateRootCert() (*CertInfo, error) {

	pk, err := rsa.GenerateKey(rand.Reader, c.PrivateKeyBits)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key: %v", err)
	}

	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("cannot generate serialNumber: %v", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{c.Organization},
			OrganizationalUnit: []string{c.OrganizationalUnit},
			Locality:           []string{c.Locality},
			Province:           []string{c.Province},
			StreetAddress:      []string{c.StreetAddress},
			Country:            []string{c.Country},
			CommonName:         c.CommonName,
		},
		NotBefore: now.Add(-5 * time.Minute).UTC(),
		NotAfter:  now.Add(c.ValidityPeriod).UTC(),

		SubjectKeyId:          bigIntHash(pk.N),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SignatureAlgorithm:    c.SignatureAlgorithm,
	}
	cert, derBytes, err := createCertificate(&template, &template, &pk.PublicKey, pk)
	if err != nil {
		return nil, err
	}
	return &CertInfo{
		Cert:        cert,
		certDERData: derBytes,
		PrivateKey:  pk,
	}, nil
}

func (c *CertConfig) GenerateCert(signer *CertInfo) (*CertInfo, error) {
	pk, err := rsa.GenerateKey(rand.Reader, c.PrivateKeyBits)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key: %v", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: new(big.Int),
		Subject: pkix.Name{
			Organization:       []string{c.Organization},
			OrganizationalUnit: []string{c.OrganizationalUnit},
			Locality:           []string{c.Locality},
			Province:           []string{c.Province},
			StreetAddress:      []string{c.StreetAddress},
			Country:            []string{c.Country},
			CommonName:         c.CommonName,
		},
		NotBefore:          now.Add(-5 * time.Minute).UTC(),
		NotAfter:           now.Add(c.ValidityPeriod).UTC(),
		PublicKeyAlgorithm: x509.RSA,

		IPAddresses: c.IPAddresses,
		DNSNames:    c.DNSNames,

		SubjectKeyId: bigIntHash(pk.N),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
	}
	cert, derBytes, err := createCertificate(&template, signer.Cert, &pk.PublicKey, signer.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &CertInfo{
		Cert:        cert,
		certDERData: derBytes,
		PrivateKey:  pk,
	}, nil
}

func CertLoad(certPath, privateKeyPath string) (*CertInfo, error) {
	cert := &CertInfo{}

	if certPath != "" {
		certFile, err := os.Open(certPath)
		if err != nil {
			return nil, err
		}
		defer certFile.Close()
		b, err := ioutil.ReadAll(certFile)
		if err != nil {
			return nil, err
		}
		p, rest := pem.Decode(b)
		if len(rest) > 0 {
			return nil, errors.New("failed to decode cert")
		}
		cert.certDERData = p.Bytes

		c, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, err
		}
		cert.Cert = c
	}

	if privateKeyPath != "" {
		certPrivateKeyFile, err := os.Open(privateKeyPath)
		if err != nil {
			return nil, err
		}
		defer certPrivateKeyFile.Close()
		b, err := ioutil.ReadAll(certPrivateKeyFile)
		if err != nil {
			return nil, err
		}
		p, rest := pem.Decode(b)
		if len(rest) > 0 {
			return nil, errors.New("failed to decode cert private key")
		}
		pk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
		if err != nil {
			return nil, err
		}
		cert.PrivateKey = pk
	}

	return cert, nil
}

func CertFileLoad(certFile, certPrivateKeyFile io.Reader) (*CertInfo, error) {
	cert := &CertInfo{}

	if certFile != nil {
		b, err := ioutil.ReadAll(certFile)
		if err != nil {
			return nil, err
		}
		p, rest := pem.Decode(b)
		if len(rest) > 0 {
			return nil, errors.New("failed to decode cert")
		}
		cert.certDERData = p.Bytes

		c, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, err
		}
		cert.Cert = c
	} else {
		return nil, errors.New("cert is nil")
	}

	if certPrivateKeyFile != nil {
		b, err := ioutil.ReadAll(certPrivateKeyFile)
		if err != nil {
			return nil, err
		}
		p, rest := pem.Decode(b)
		if len(rest) > 0 {
			return nil, errors.New("failed to decode cert private key")
		}
		pk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
		if err != nil {
			return nil, err
		}
		cert.PrivateKey = pk
	} else {
		return nil, errors.New("cert private key is nil")
	}

	return cert, nil
}

func createCertificate(template, parent *x509.Certificate, pub, priv interface{}) (cert *x509.Certificate, derBytes []byte, err error) {
	derBytes, err = x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("canot create certificate: %v", err)
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse new certificate: %v", err)
	}
	if len(certs) != 1 {
		return nil, nil, fmt.Errorf("need exactly one certificate")
	}
	return certs[0], derBytes, nil
}

func bigIntHash(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}
