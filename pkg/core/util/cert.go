package util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

func GenerateRootCert() (cert *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	notBefore := time.Now()
	notAfter := notBefore.AddDate(10, 0, 0)
	subject := pkix.Name{
		Organization: []string{"CheckMate Root Org."},
		CommonName:   "CheckMate Root CA",
	}
	isCA := true
	keUsage := x509.KeyUsageCertSign

	return genCert(notBefore, notAfter, isCA, keUsage, subject, []string{})
}

// generates an ECDSA cert
func genCert(notBefore, notAfter time.Time, isCA bool,
	keyUsage x509.KeyUsage, subject pkix.Name, dnsNames []string) (cert *x509.Certificate, key *ecdsa.PrivateKey, err error) {

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	serialNo, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}

	cert = &x509.Certificate{
		SerialNumber:          serialNo,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Subject:               subject,
	}
	if !isCA {
		cert.DNSNames = dnsNames
	}
	return
}

func GenerateLeafCertificate(rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 6, 0)
	subject := pkix.Name{
		Organization: []string{"CheckMate Self-Signed certificate"},
		CommonName:   "CheckMate certificate",
	}
	isCA := false
	keUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	dnsNames := []string{"localhost"}
	return genCert(notBefore, notAfter, isCA, keUsage, subject, dnsNames)
}

// DER encode certificate
func EncodeCert(cert, signingCert *x509.Certificate, pubKey *ecdsa.PublicKey, signingKey *ecdsa.PrivateKey) ([]byte, error) {
	cb, err := x509.CreateCertificate(rand.Reader, cert, signingCert, pubKey, signingKey)
	if err != nil {
		return cb, err
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cb})
	return buf.Bytes(), err
}

// Encode private key
func EncodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	var buf bytes.Buffer
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return buf.Bytes(), err
	}

	err = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return buf.Bytes(), err
}
