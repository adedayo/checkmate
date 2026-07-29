package ldapsync

import (
	"fmt"
	"net"
	"strings"
)

type AuthResult struct {
	Success      bool
	ErrorMessage string
}

type LDAPRecords struct {
	Entries        []*LDAPEntry
	config         *LDAPSyncConfig
	users, groups  []*LDAPEntry
	UsersAndGroups UsersAndGroups
}

func (sr LDAPRecords) GetUsersAndGroups() UsersAndGroups {

	users := sr.GetUsers()
	groups := sr.GetGroups()

	ug := UsersAndGroups{
		Users:  make([]User, len(users)),
		Groups: make([]Group, len(groups)),
	}

	for i, g := range groups {
		ug.Groups[i] = Group{
			DN: g.DN,
			ID: simpleName(g.DN),
		}
	}
	for i, u := range users {
		ug.Users[i] = User{
			DN: u.DN,
			ID: simpleName(u.DN),
		}

		for j, g := range ug.Groups {
			if sr.IsMember(u.DN, g.DN) {
				ug.Groups[j].Members = append(ug.Groups[j].Members, u.DN)
			}
		}
	}

	return ug

}

func simpleName(dn string) string {
	x := strings.Split(strings.Split(dn, ",")[0], "=")
	if len(x) > 1 {
		return x[1]
	}
	return "" //error
}

func (sr *LDAPRecords) GetUsers() []*LDAPEntry {

	if sr.users == nil { //only  do this once
		var ents []*LDAPEntry
		for _, e := range sr.Entries {
			if sr.config.UserFilter.Matches(e) {
				ents = append(ents, e)
			}
		}
		sr.users = ents
	}
	return sr.users
}

func (sr *LDAPRecords) GetGroups() []*LDAPEntry {
	if sr.groups == nil { //only  do this once
		var ents []*LDAPEntry
		for _, e := range sr.Entries {
			if sr.config.GroupFilter.Matches(e) {
				ents = append(ents, e)
			}
		}
		sr.groups = ents
	}

	return sr.groups
}

// checks whether a user distinguished name (DN) belongs to the group specified as a DN
func (sr *LDAPRecords) IsMember(user, group string) bool {
	var uu, gg *LDAPEntry
	for _, g := range sr.GetGroups() {
		if g.DN == group {
			gg = g
		}
	}

	if gg == nil { // group not found
		return false
	}

	for _, u := range sr.GetUsers() {
		if u.DN == user {
			uu = u
		}
	}

	if uu == nil { // user not found
		return false
	}

	//found a user and group. Determine if user belongs to group
	return sr.config.GroupMembership.IsMember(uu, gg)
}

type LDAPAuthData struct {
	Server   string `json:"server"`
	Port     string `json:"port"`
	TLS      string `json:"tls"`
	UID      string `json:"uid"`
	URDNs    string `json:"urdns"`
	User     string `json:"user"`
	Password string `json:"pwd"`
}

type LDAPConfig struct {
	Server                 string
	RequiresAuthentication bool   `json:"requiresAuth"` //if sync requires authentication, in which case sync username and passwords below must be set
	SyncUserName           string `json:"syncUserName"` //distinguished name of an administrative user that the application will use when connecting to the directory server. For Active Directory, the user should be a member of the built-in administrator group
	SyncPassword           string `json:"syncPassword"`
	TLS, StartTLS          bool
	Port                   *string //389 if not set
}

type LDAPSyncConfig struct {
	// ServerConfig    LDAPConfig
	Server                 string                    `json:"server"`
	RequiresAuthentication bool                      `json:"syncRequiresAuth"` //if sync requires authentication, in which case sync username and passwords below must be set
	SyncUserName           string                    `json:"syncUserName"`     //distinguished name of an administrative user that the application will use when connecting to the directory server. For Active Directory, the user should be a member of the built-in administrator group
	SyncPassword           string                    `json:"syncUserPassword"`
	TLS                    string                    `json:"tls"`     // options: none, tls, starttls
	Port                   *string                   `json:"port"`    //389 if not set
	BaseDNs                []string                  `json:"baseDNs"` //Base DNs to search from `json:"baseDNs"`
	GroupFilter            LDAPFilter                `json:"groupFilter"`
	UserFilter             LDAPFilter                `json:"userFilter"`
	GroupMembership        GroupMembershipAssociator `json:"groupMembership"` // how we determine which groups the user belongs to
}

func (conf LDAPSyncConfig) GetDialAddr() string {
	port := "389"
	if conf.Port != nil {
		port = *conf.Port
	}
	return net.JoinHostPort(conf.Server, port)
}

func (conf LDAPSyncConfig) GetDialURL() string {
	port := "389"
	if conf.Port != nil {
		port = *conf.Port
	}
	return "ldap://" + net.JoinHostPort(conf.Server, port)
}

// Prevent LDAP Injection
// See https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
// TODO: Implement the sanitization
func (conf LDAPSyncConfig) Sanitize() LDAPSyncConfig {
	for i := range conf.BaseDNs {
		conf.BaseDNs[i] = sanitiseDN(conf.BaseDNs[i])
	}
	return conf
}

// TODO
func sanitiseDN(d string) string {
	return d
}

type LDAPEntry struct {
	DN         string
	Attributes []LDAPAttribute
}

func (ent LDAPEntry) GetAttribute(attribute string) (bool, []string) {
	for _, att := range ent.Attributes {
		if att.Name == attribute {
			return true, att.Values
		}
	}
	return false, []string{}
}

// LDAPAttribute is an LDAP attribute that has a name and a list of values
type LDAPAttribute struct {
	Name   string
	Values []string
}

func (att LDAPAttribute) String() string {
	return fmt.Sprintf("%s -> %s", att.Name, att.Values)
}

type UsersAndGroups struct {
	Users  []User
	Groups []Group
}

type User struct {
	ID string //simple name johnd
	DN string // e.g. uid=johnd,ou=users,dc=company,dc=com
}

type Group struct {
	ID      string
	DN      string
	Members []string //user DNs
}
