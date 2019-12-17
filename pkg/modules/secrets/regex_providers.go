package secrets

import (
	"regexp"
	"strings"

	"github.com/adedayo/checkmate/pkg/common"
	"github.com/adedayo/checkmate/pkg/common/code"
	"github.com/adedayo/checkmate/pkg/common/diagnostics"
	"github.com/adedayo/checkmate/pkg/common/util"
)

var (
	//JavaFinder provides secret detection in Java-like programming languages
	// JavaFinder                     MatchProvider
	descHardCodedSecretAssignment  = "Hard-coded secret assignment"
	descVarSecret                  = "Variable name suggests it is a secret"
	descEncodedSecret              = "Value looks suspiciously like an encoded secret (e.g. Base64 or Hex encoded)"
	descSecretUnbrokenString       = "Unbroken string may be a secret"
	descConstantAssignment         = "Constant assignment to a variable name that suggests it is a secret"
	descHardCodedSecret            = "Hard-coded secret"
	descDefaultSecret              = "Default or common secret value"
	descCommonSecret               = "Value contains or appears to be a common credential"
	descSuspiciousSecret           = "Value looks suspiciously like a secret"
	descHighEntropy                = "Value has a high entropy, may be a secret"
	descNotSecret                  = "Value does not appear to be a secret"
	unusualPasswordStartCharacters = `<>&^%?#({|/`

	assignmentProviderID       = "SecretAssignment"
	confAssignmentProviderID   = "ConfSecretAssignment"
	cppAssignmentProviderID    = "CPPSecretAssignment"
	longTagValueProviderID     = "LongTagValueSecretAssignment"
	secretTagProviderID        = "CommonSecretTagValue"
	jsonAssignmentProviderID   = "JSONSecretAssignment"
	yamlAssignmentProviderID   = "YAMLSecretAssignment"
	arrowAssignmentProviderID  = "ArrowSecretAssignment"
	defineAssignmentProviderID = "DefineSecretAssignment"
	tagAssignmentProviderID    = "TagSecretAssignment"

	longStringProviderID   = "LongString"
	secretStringProviderID = "SecretString"
)

//GetFinderForFileType returns the appropriate MatchProvider based on the file type hint
func GetFinderForFileType(fileType string) MatchProvider {
	switch strings.ToLower(fileType) {
	case ".java", ".scala", ".kt", ".go":
		return NewJavaFinder()
	case ".c", ".cpp", ".cc", ".c++", ".h++", ".hh", ".hpp":
		return NewCPPSecretsFinders()
	case ".xml":
		return NewXMLSecretsFinders()
	case ".json":
		return NewJSONSecretsFinders()
	case ".yaml", ".yml":
		return NewYamlSecretsFinders()
	case ".rb":
		return NewRubySecretsFinders()
	case ".erb":
		return NewERubySecretsFinders()
	case ".conf":
		return NewConfigurationSecretsFinder()
	default:
		return defaultFinder()
	}
}

func defaultFinder() MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(assignmentProviderID, secretAssignment),
			makeSecretStringFinder(secretStringProviderID, secretStrings),
			makeSecretStringFinder(longStringProviderID, longStrings),
		},
	}
}

//NewJavaFinder provides secret detection in Java-like programming languages
func NewJavaFinder() MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(assignmentProviderID, secretAssignment),
			makeSecretStringFinder(secretStringProviderID, secretStrings),
			makeSecretStringFinder(longStringProviderID, longStrings),
		},
	}
}

//MatchProvider provides regular expressions and other facilities for locating secrets in source data
type MatchProvider interface {
	// common.WhitelistProvider
	GetFinders() []common.SourceToSecurityDiagnostics
}

//RegexFinder provides secret detection using regular expressions
type RegexFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	res           []*regexp.Regexp
	lineKeeper    *util.LineKeeper
	providerID    string
	provideSource bool
}

//GetRegularExpressions returns the underlying compiled regular expressions
func (finder RegexFinder) GetRegularExpressions() []*regexp.Regexp {
	return finder.res
}

//Consume allows a source processor receive `source` data streamed in "chunks", with `startIndex` indicating the
//character location of the first character in the stream
func (finder *RegexFinder) Consume(startIndex int, source string) {
}

//SetLineKeeper allows this source consumer to keep track of `code.Position`
func (finder *RegexFinder) SetLineKeeper(lk *util.LineKeeper) {
	finder.lineKeeper = lk
}

//End is used to signal to the consumer that the source stream has ended
func (finder *RegexFinder) End() {

}

//ShouldProvideSourceInDiagnostics toggles whether source evidence should be provided with diagnostics, defaults to false
func (finder *RegexFinder) ShouldProvideSourceInDiagnostics(provideSource bool) {
	finder.provideSource = provideSource
}

type defaultMatchProvider struct {
	finders []common.SourceToSecurityDiagnostics
}

func (dmp defaultMatchProvider) GetFinders() []common.SourceToSecurityDiagnostics {
	return dmp.finders
}

func (dmp defaultMatchProvider) ShouldWhitelist(pathContext, value string) bool {
	return false
}

//NewConfigurationSecretsFinder is a `MatchProvider` for finding secrets in configuration `.conf` files
func NewConfigurationSecretsFinder() MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(confAssignmentProviderID, confAssignment),
			makeAssignmentFinder(assignmentProviderID, secretAssignment),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString),
			makeSecretStringFinder(secretStringProviderID, secretStrings),
			makeSecretStringFinder(longStringProviderID, longStrings),
		},
	}
}

//NewCPPSecretsFinders is a `MatchProvider` for finding secrets in files with C++-like content
func NewCPPSecretsFinders() MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(cppAssignmentProviderID, secretCPPAssignment),
			makeAssignmentFinder(defineAssignmentProviderID, secretDefine),
			makeSecretStringFinder(secretStringProviderID, secretStrings),
			makeSecretStringFinder(longStringProviderID, longStrings),
		},
	}
}

//NewXMLSecretsFinders is a `MatchProvider` for finding secrets in files with XML content
func NewXMLSecretsFinders() MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(tagAssignmentProviderID, secretTags),
			makeAssignmentFinder(assignmentProviderID, secretAssignment),
			makeSecretStringFinder(secretStringProviderID, secretStrings),
			makeSecretStringFinder(longStringProviderID, longStrings),
		},
	}
}

//NewJSONSecretsFinders is a `MatchProvider` for finding secrets in files with JSON content
func NewJSONSecretsFinders() MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool),
			makeSecretStringFinder(longStringProviderID, longStrings),
		},
	}
}

//NewRubySecretsFinders is a `MatchProvider` for finding secrets in files with Ruby content
func NewRubySecretsFinders() MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(tagAssignmentProviderID, secretTags),
			makeAssignmentFinder(assignmentProviderID, secretAssignment),
			makeAssignmentFinder(longTagValueProviderID, longTagValues),
			makeAssignmentFinder(secretTagProviderID, secretTagValues),
			makeSecretStringFinder(secretStringProviderID, secretStrings),
			makeSecretStringFinder(longStringProviderID, longStrings),
		},
	}
}

//NewERubySecretsFinders is a `MatchProvider` for finding secrets in files with ERuby content
func NewERubySecretsFinders() MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(tagAssignmentProviderID, secretTags),
			makeAssignmentFinder(assignmentProviderID, secretAssignment),
			makeAssignmentFinder(longTagValueProviderID, longTagValues),
			makeAssignmentFinder(secretTagProviderID, secretTagValues),
			makeSecretStringFinder(secretStringProviderID, secretStrings),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool),
			makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString),
			makeSecretStringFinder(longStringProviderID, longStrings),
		},
	}
}

//NewYamlSecretsFinders is a `MatchProvider` for finding secrets in files with YAML content
func NewYamlSecretsFinders() MatchProvider {
	return &defaultMatchProvider{
		finders: []common.SourceToSecurityDiagnostics{
			makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment),
			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString),
			makeSecretStringFinder(longStringProviderID, longStrings),
		},
	}
}

func makeAssignmentFinder(providerID string, re *regexp.Regexp) *assignmentFinder {
	var sa assignmentFinder
	sa.providerID = providerID
	sa.res = []*regexp.Regexp{re}
	return &sa
}

func makeSecretStringFinder(providerID string, re *regexp.Regexp) *secretStringFinder {
	var sf secretStringFinder
	sf.providerID = providerID
	sf.res = []*regexp.Regexp{re}
	return &sf
}

type secretFinder struct {
	RegexFinder
	diagnostics.DefaultSecurityDiagnosticsProvider
}

type assignmentFinder struct {
	secretFinder
}

func (sa *assignmentFinder) Consume(startIndex int, source string) {
	for _, re := range sa.GetRegularExpressions() {
		matches := re.FindAllStringSubmatchIndex(source, -1)
		for _, match := range matches {
			if len(match) == 6 { //we are expecting 6 elements
				start := match[0]
				end := match[1]

				rhsStart := match[4] //beginning of assigned value
				assignedVal := source[rhsStart:end]
				assignedVal = strings.Trim(assignedVal, `"'`+"`")
				variable := strings.ToLower(source[match[2]:match[3]])
				evidence := detectSecret(assignedVal)
				if strings.Contains(variable, "passphrase") {
					evidence.Description = descHardCodedSecret
					evidence.Confidence = diagnostics.High

				}

				diagnostic := diagnostics.SecurityDiagnostic{
					Justification: diagnostics.Justification{
						Headline: diagnostics.Evidence{
							Description: descHardCodedSecretAssignment,
							Confidence:  diagnostics.Medium,
						},
						Reasons: []diagnostics.Evidence{
							{
								Description: descVarSecret,
								Confidence:  diagnostics.High,
							},
							evidence},
					},
					Range: code.Range{
						Start: sa.lineKeeper.GetPositionFromCharacterIndex(startIndex + start),
						End:   sa.lineKeeper.GetPositionFromCharacterIndex(startIndex + end - 1),
					},
					ProviderID: sa.providerID,
				}
				if diagnostic.Justification.Reasons[1].Confidence != diagnostics.Low {
					diagnostic.Justification.Headline.Confidence = diagnostics.High
				}
				if diagnostic.Justification.Reasons[1].Description == descNotSecret &&
					diagnostic.Justification.Headline.Confidence > diagnostics.Medium {
					diagnostic.Justification.Headline.Confidence = diagnostics.Medium
				}
				if sa.provideSource {
					s := source[start:end]
					diagnostic.Source = &s
				}
				sa.Broadcast(diagnostic)
			}
		}
	}

}

type secretStringFinder struct {
	secretFinder
}

func (sf *secretStringFinder) Consume(startIndex int, source string) {
	for _, re := range sf.GetRegularExpressions() {
		matches := re.FindAllStringSubmatchIndex(source, -1)
		for _, match := range matches {
			if len(match) == 4 && space.FindAllStringIndex(source[match[0]:match[1]], -1) == nil {
				start := match[0]
				end := match[1]

				value := source[start:end]
				value = strings.Trim(value, `"'`+"`")
				evidence := detectSecret(value)

				diagnostic := diagnostics.SecurityDiagnostic{
					Justification: diagnostics.Justification{
						Headline: diagnostics.Evidence{
							Description: descSecretUnbrokenString,
							Confidence:  diagnostics.Medium,
						},
						Reasons: []diagnostics.Evidence{
							{
								Description: descSecretUnbrokenString,
								Confidence:  diagnostics.Medium,
							},
							evidence},
					},
					Range: code.Range{
						Start: sf.lineKeeper.GetPositionFromCharacterIndex(startIndex + start),
						End:   sf.lineKeeper.GetPositionFromCharacterIndex(startIndex + end - 1),
					},
					ProviderID: sf.providerID,
				}
				if diagnostic.Justification.Reasons[1].Confidence == diagnostics.High {
					diagnostic.Justification.Headline.Confidence = diagnostics.High
				}
				if sf.provideSource {
					s := source[start:end]
					diagnostic.Source = &s
				}
				sf.Broadcast(diagnostic)
			}
		}
	}

}
