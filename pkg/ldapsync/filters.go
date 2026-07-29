package ldapsync

import (
	"regexp"
	"strings"
)

// Used for determining group membership of users
type GroupMembershipAssociator struct {
	Constraints     []Constraint                `json:"constraints"`
	Operator        LDAPFilterOperator          `json:"operator"` // logical operator to chain this and AdditionalRules for more complex membership conditions
	AdditionalRules []GroupMembershipAssociator `json:"additionalRules"`
}

type Constraint struct {
	UserAttribute  string //user attribute to match against the group attribute, e.g. memberOf
	GroupAttribute string // Group attribute to match against a user attribute e.g. DN
}

func (c Constraint) IsMember(user, group *LDAPEntry) bool {
	if strings.ToLower(c.UserAttribute) == "dn" {
		if strings.ToLower(c.GroupAttribute) == "dn" {
			return user.DN == group.DN
		} else {
			//some group attribute
			return group.ContainsAttributeValue(c.GroupAttribute, user.DN)
		}
	} else {
		//some user attribute
		if strings.ToLower(c.GroupAttribute) == "dn" {
			return user.ContainsAttributeValue(c.UserAttribute, group.DN)
		} else {
			//some group attribute
			if exist, uValues := user.GetAttribute(c.UserAttribute); exist {
				if gexist, gValues := group.GetAttribute(c.GroupAttribute); gexist {
					for _, uv := range uValues {
						for _, gv := range gValues {
							if uv == gv {
								return true //found a match
							}
						}
					}
					return false // no match

				} else {
					return false // group attribute doesn't exist
				}
			} else {
				return false // user attribute doesn't exist
			}
		}
	}
}

// determines whether a user based on a user LDAP attribute belongs to a group e.g. {UserAttribute: uid, GroupAttribute: memberUid}
func (gmf GroupMembershipAssociator) IsMember(user, group *LDAPEntry) bool {

	switch gmf.Operator {
	case And:
		for _, c := range gmf.Constraints {
			if !c.IsMember(user, group) {
				return false // short circuit
			}
		}
		//all the constraints are valid, check additional rules
		for _, gma := range gmf.AdditionalRules {
			if !gma.IsMember(user, group) {
				return false // short circuit
			}
		}
		// if we reach this point, everything checks out
		return true

	case Or:

		for _, c := range gmf.Constraints {
			if c.IsMember(user, group) {
				return true // short circuit
			}
		}

		for _, gma := range gmf.AdditionalRules {
			if gma.IsMember(user, group) {
				return true // short circuit
			}
		}
		//nothing checks out
		return false

	default:
		return false
	}

}

type LDAPFilterOperator int

const (
	And LDAPFilterOperator = iota
	Or
)

// Filter LDAP entities with the struct
// e.g. (&(memberof=cn=access-checkmate,cn=groups,cn=accounts,dc=example,dc=org)(cn=*Developers*))
// {Operator: And, Filters: []FilterExpression{{Name: "memberof", Value: "cn=access-checkmate,cn=groups,cn=accounts,dc=example,dc=org"},
// {Name: "cn", Value: "*Developers*"}}}
type LDAPFilter struct {
	Operator     LDAPFilterOperator
	Filters      []FilterExpression
	FilterGroups []LDAPFilter
	compiled     bool
}

func (lf *LDAPFilter) compile() {
	for i := range lf.Filters {
		lf.Filters[i].compile()
	}

	for i := range lf.FilterGroups {
		lf.FilterGroups[i].compile()
	}

	lf.compiled = true
}

func (f *LDAPFilter) Matches(ent *LDAPEntry) bool {

	if ent == nil {
		return false //bail out on nonsensical entry
	}

	if !f.compiled {
		f.compile()
	}

	m := false
	switch f.Operator {
	case And:
		for _, ff := range f.Filters {
			if strings.ToLower(ff.Name) == "dn" {
				if ent.DN == ff.Value {
					m = true
				} else {
					return false // short-circuit on wrong DN
				}
			} else {
				if !ent.ContainsAttribute(&ff) {
					return false // short-circuit entity with non-matching attribute
				} else {
					m = true
				}
			}
		}
		for _, fg := range f.FilterGroups {
			if fg.Matches(ent) {
				m = true
			} else {
				return false // short-circuit any group that does not match
			}
		}
	case Or:
		for _, ff := range f.Filters {
			if strings.ToLower(ff.Name) == "dn" {
				if ent.DN == ff.Value {
					return true // short-circuit on correct DN
				}
			} else {
				if ent.ContainsAttribute(&ff) {
					return true // short-circuit entity with matching attribute
				}
			}
		}
		for _, fg := range f.FilterGroups {
			if fg.Matches(ent) {
				return true // short-circuit on any group match
			}
		}
	}

	return m
}

func (ent *LDAPEntry) ContainsAttributeValue(attr, value string) bool {
	for _, att := range ent.Attributes {
		if att.Name == attr {
			for _, v := range att.Values {
				if v == value {
					return true
				}
			}
		}
	}
	return false

}

func (ent *LDAPEntry) ContainsAttribute(ff *FilterExpression) bool {
	ff.compile()
	for _, att := range ent.Attributes {
		if att.Name == ff.Name {
			for _, v := range att.Values {
				if ff.compiledValue.MatchString(v) {
					return true
				}
			}
		}
	}
	return false
}

type NameValue struct {
	Name, Value string
}

type FilterExpression struct {
	Name, Value          string
	compiledValue        *regexp.Regexp
	compiledSuccessfully bool
}

func (fe *FilterExpression) compile() {
	if fe.compiledSuccessfully {
		return //compile once
	}
	re, err := regexp.Compile(fe.Value)
	if err == nil {
		fe.compiledValue = re
		fe.compiledSuccessfully = true
	}
}
