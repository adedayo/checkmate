package gitutils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
)

// AcquisitionErrorKind classifies why acquiring a scan target failed.
type AcquisitionErrorKind string

const (
	AcqErrAuth       AcquisitionErrorKind = "auth_failed"
	AcqErrNotFound   AcquisitionErrorKind = "not_found"
	AcqErrNetwork    AcquisitionErrorKind = "network"
	AcqErrTLS        AcquisitionErrorKind = "tls"
	AcqErrInvalidURL AcquisitionErrorKind = "invalid_url"
	AcqErrIO         AcquisitionErrorKind = "io"
)

// AcquisitionFailure records a single failed target acquisition with any
// credentials stripped from Target and Message.
type AcquisitionFailure struct {
	Target    string               `json:"target"`
	ErrorKind AcquisitionErrorKind `json:"errorKind"`
	Message   string               `json:"message"`
}

// AcquisitionReport summarises target acquisition outcomes for a scan.
type AcquisitionReport struct {
	Attempted     int                  `json:"attempted"`
	Succeeded     int                  `json:"succeeded"`
	Failed        int                  `json:"failed"`
	Failures      []AcquisitionFailure `json:"failures,omitempty"`
	RetainedPaths map[string]string    `json:"retainedPaths,omitempty"`
}

// ClassifyCloneError maps go-git, TLS, network, and filesystem errors into a
// stable AcquisitionErrorKind so callers can surface actionable guidance.
func ClassifyCloneError(err error) AcquisitionErrorKind {
	if err == nil {
		return ""
	}

	if errors.Is(err, ErrServiceNotFound) ||
		errors.Is(err, transport.ErrAuthenticationRequired) ||
		errors.Is(err, transport.ErrAuthorizationFailed) {
		return AcqErrAuth
	}

	if errors.Is(err, transport.ErrRepositoryNotFound) {
		return AcqErrNotFound
	}

	if errors.Is(err, transport.ErrInvalidAuthMethod) {
		return AcqErrAuth
	}

	var unknownAuthErr x509.UnknownAuthorityError
	var certInvalidErr x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	var tlsRecordErr tls.RecordHeaderError
	if errors.As(err, &unknownAuthErr) ||
		errors.As(err, &certInvalidErr) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &tlsRecordErr) {
		return AcqErrTLS
	}

	var netErr net.Error
	var opErr *net.OpError
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) || errors.As(err, &opErr) || errors.As(err, &netErr) {
		return AcqErrNetwork
	}

	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		// Distinguish missing/unreadable SSH key from generic IO?
		return AcqErrIO
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Err != nil {
			inner := ClassifyCloneError(urlErr.Err)
			if inner != "" && inner != AcqErrIO {
				return inner
			}
		}
		return AcqErrInvalidURL
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "authentication required") ||
		strings.Contains(msg, "authorization failed") ||
		strings.Contains(msg, "401") ||
		strings.Contains(msg, "403") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "ssh: handshake failed") ||
		strings.Contains(msg, "ssh: unable to authenticate") ||
		strings.Contains(msg, "could not read username") ||
		strings.Contains(msg, "git service not found"):
		return AcqErrAuth
	case strings.Contains(msg, "repository not found") ||
		strings.Contains(msg, "404") ||
		strings.Contains(msg, "does not exist"):
		return AcqErrNotFound
	case strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "certificate"):
		return AcqErrTLS
	case strings.Contains(msg, "invalid url") ||
		strings.Contains(msg, "unsupported scheme") ||
		strings.Contains(msg, "missing protocol scheme") ||
		strings.Contains(msg, "malformed"):
		return AcqErrInvalidURL
	case strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "unexpected eof"):
		return AcqErrNetwork
	default:
		return AcqErrIO
	}
}
