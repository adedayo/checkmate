package ldapsync

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/go-ldap/ldap/v3"
)

// sync an Do service based on provided sync configuration
func Do(config LDAPSyncConfig) (result LDAPRecords, err error) {
	config = config.Sanitize()
	result.config = &config
	var l *ldap.Conn
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //TODO: support self-signed CAs
	}

	if config.TLS == "tls" {
		l, err = ldap.DialTLS("tcp", config.GetDialAddr(), tlsConfig)
		if err != nil {
			return
		}
	} else {
		l, err = ldap.DialURL(config.GetDialURL())
		if err != nil {
			return
		}
		if config.TLS == "starttls" {
			err = l.StartTLS(tlsConfig)
			if err != nil {
				return
			}
		}
	}

	if err != nil {
		return
	}
	defer l.Close()

	if config.RequiresAuthentication {
		err = l.Bind(config.SyncUserName, config.SyncPassword)
		if err != nil {
			return
		}
	}

	for _, baseDN := range config.BaseDNs {
		searchRequest := ldap.NewSearchRequest(
			baseDN, // The base dn to search
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=*))", // The filter to apply - get everything
			[]string{},           // A list attributes to retrieve - get all attributes
			[]ldap.Control{},
		)

		sr, e := l.SearchWithPaging(searchRequest, 5 /*limit pagination size to 5*/)
		if e != nil {
			err = e
			return
		}

		for _, entry := range sr.Entries {
			ent := LDAPEntry{
				DN:         entry.DN,
				Attributes: make([]LDAPAttribute, len(entry.Attributes)),
			}
			for i, att := range entry.Attributes {
				ent.Attributes[i] = LDAPAttribute{
					Name:   att.Name,
					Values: att.Values,
				}
			}
			result.Entries = append(result.Entries, &ent)
		}
	}
	return

}

// Authenticate against LDAP service. Successful authentication if AuthResult.Success = true
func Auth(data LDAPAuthData) (auth AuthResult, err error) {

	dialURL := net.JoinHostPort(data.Server, data.Port)
	var l *ldap.Conn
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //TODO: support self-signed CAs
	}

	if data.TLS == "tls" {
		l, err = ldap.DialTLS("tcp", dialURL, tlsConfig)
		if err != nil {
			auth.ErrorMessage = err.Error()
			return
		}
	} else {
		l, err = ldap.DialURL("ldap://" + dialURL)
		if err != nil {
			auth.ErrorMessage = err.Error()
			return
		}
		if data.TLS == "starttls" {
			err = l.StartTLS(tlsConfig)
			if err != nil {
				auth.ErrorMessage = err.Error()
				return
			}
		}
	}

	if err != nil {
		auth.ErrorMessage = err.Error()
		return
	}
	defer l.Close()

	username := fmt.Sprintf("%s=%s,%s", data.UID, data.User, data.URDNs)

	err = l.Bind(username, data.Password)
	if err != nil {
		auth.ErrorMessage = err.Error()
		auth.Success = false
		return auth, nil //failed authentication, do not propagate that error to the auth API
	}

	auth.Success = true

	return

}
