package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"

	"github.com/adedayo/checkmate/pkg/core/code"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

var (
	dash = "-"
)

// SecurityDiagnostic describes a security issue
type SecurityDiagnostic struct {
	Justification  Justification `json:"justification,omitempty"`
	Range          code.Range    `json:"range,omitempty"`
	RawRange       CharRange     `json:"rawRange,omitempty"`
	HighlightRange code.Range    `json:"highlightRange,omitempty"`
	//Source code evidence optionally provided
	Source *string `json:"source,omitempty"`
	//SHA256 checksum is an optional SHA256 hash of the secret. High-security environments
	//may want to consider using an HMAC or similar and ommitting source from the reports
	SHA256 *string `json:"sha256,omitempty"`
	//Location is an optional value that could contain filepath or URI of resource that this diagnostic applies to
	Location *string `json:"location,omitempty"`
	//used for identifying the source of the diagnostics
	ProviderID      *string   `json:"providerID,omitempty"`
	Excluded        bool      //indicates whether or not this diagnostics has been excluded
	Tags            *[]string `json:"tags,omitempty"` //optionally annotate diagnostic with tags, e.g. "test"
	RepositoryIndex int       `json:"-"`              //used to track issue repository internally, not serialised
}

func (sd *SecurityDiagnostic) CSVHeaders(extraHeaders ...string) []string {
	return append([]string{
		`Code`, //Source
		`Severity`,
		`Description`,
		`File`,          //Location
		`File Location`, //Range Start Position
		`SHA256`,
		`Tags`,
		`Detector ID`, // ProviderID
		`Repository`,
	}, extraHeaders...)
}

// Derives additional headers from Tags, sorted in alphabetic order
func GetExtraHeaders(diags []*SecurityDiagnostic) []string {
	headers := make(map[string]bool)
	for _, sd := range diags {
		if sd.Tags != nil {
			for _, tag := range *sd.Tags {
				if strings.Contains(tag, "=") {
					h := strings.Split(tag, "=")[0] //take the key
					headers[h] = true
				}
			}
		}
	}
	diags = nil
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func nilAsDash(x *string) string {
	if x == nil {
		return dash
	}
	return *x
}

func nilArrayAsDash(x *[]string) string {
	if x == nil {
		return dash
	}
	return strings.Join(*x, " ")
}

func (sd *SecurityDiagnostic) CSVValues(extraHeaders ...string) []string {
	rng := adjustRange(sd.Range)
	loc := fmt.Sprintf(`Line: %d Column: %d`, rng.Start.Line, rng.Start.Character)
	location := nilAsDash(sd.Location)
	repository := location
	if strings.Contains(location, ".git/") {
		repository = strings.Split(location, ".git/")[0] + ".git"
	}
	return emptyAsDash(append([]string{
		nilAsDash(sd.Source),
		sd.Justification.Headline.Confidence.String(),
		sd.Justification.Headline.Description,
		location,
		loc,
		nilAsDash(sd.SHA256),
		nilArrayAsDash(sd.Tags),
		nilAsDash(sd.ProviderID),
		repository,
	}, additionalValues(sd.Tags, extraHeaders...)...))
}

// replace empty values with a dash
func emptyAsDash(data []string) []string {
	for i, v := range data {
		if strings.TrimSpace(v) == "" {
			data[i] = dash
		}
	}

	return data
}

func additionalValues(tags *[]string, extraHeaders ...string) []string {
	index := map[string]int{}
	for i, v := range extraHeaders {
		index[v] = i
	}
	kv := make([]string, len(extraHeaders))
	if tags != nil {
		for _, tag := range *tags {
			if strings.Contains(tag, "=") {
				vv := strings.Split(tag, "=")
				k := vv[0]
				v := vv[1]
				if i, exists := index[k]; exists {
					kv[i] = v
				}
			}
		}
		return kv
	}
	return []string{}
}

// HasTag cheks whether diagnostic has the specified tag
func (sd *SecurityDiagnostic) HasTag(tag string) bool {
	if sd.Tags == nil {
		if tag == "prod" {
			return true //prod is a virtual tag, indicated by absence of "test" tag
		}
		return false
	}
	for _, t := range *sd.Tags {
		if t == tag {
			return true
		}
	}

	//treat "prod" as a virtual tag indicated by the absence of "test" tag
	if tag == "prod" {
		for _, t := range *sd.Tags {
			if t == "test" {
				return false
			}
		}
		return true
	}
	return false
}

func (sd *SecurityDiagnostic) GetValue() string {

	if sd.Source == nil {
		return ""
	}

	return *sd.Source

}

// AddTag adds a tag to the diagnostic
func (sd *SecurityDiagnostic) AddTag(tag string) {
	if sd.Tags == nil {
		sd.Tags = &[]string{tag}
	} else {
		*sd.Tags = append(*sd.Tags, tag)
	}
}

// GoString stringify
func (sd SecurityDiagnostic) GoString() string {
	sd.Range = adjustRange(sd.Range)
	sd.HighlightRange = adjustRange(sd.HighlightRange)
	b, _ := json.Marshal(sd)
	return string(b)
}

// adjust the 0-based position to 1-based for easy human debugging
func adjustRange(in code.Range) (out code.Range) {
	out.Start.Line = in.Start.Line + 1
	out.Start.Character = in.Start.Character + 1
	out.End.Line = in.End.Line + 1
	out.End.Character = in.End.Character + 1
	return
}

// CharRange describes the location in the file where a range of "text" is found
type CharRange struct {
	StartIndex, EndIndex int64
}

func (thisRange *CharRange) Contains(thatRange *CharRange) bool {
	if thisRange.StartIndex <= thatRange.StartIndex && thatRange.EndIndex <= thisRange.EndIndex {
		return true
	}
	return false
}

// Confidence reflects the degree of confidence that we have in an assessment
type Confidence int

const (
	//informational Confidence in the assessment
	Info Confidence = iota
	//Low Confidence in the assessment
	Low
	//Medium Confidence in the assessment
	Medium
	//High Confidence in the assessment
	High
	//Critical Confidence in the assessment
	Critical
)

func (conf Confidence) String() string {
	switch conf {
	case Info:
		return "Info"
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case Critical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// GoString go stringify
func (conf Confidence) GoString() string {
	return conf.String()
}

// MarshalJSON makes a string representation of the confidence
func (conf Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(conf.String())
}

// UnmarshalJSON unmarshals a string representation of the confidence to Confidence
func (conf *Confidence) UnmarshalJSON(data []byte) error {
	cc := strings.Trim(string(data), `"`)
	switch cc {
	case Info.String():
		*conf = Info
	case Low.String():
		*conf = Low
	case Medium.String():
		*conf = Medium
	case High.String():
		*conf = High
	case Critical.String():
		*conf = Critical
	default:
		return fmt.Errorf(`unknown confidence type: %s`, cc)
	}
	return nil
}

// Evidence is an atomic piece of information that describes a security diagnostics
type Evidence struct {
	Description string     `json:"description"`
	Confidence  Confidence `json:"confidence"`
}

// Justification describes why a piece of security diagnostic has been generated
type Justification struct {
	Headline Evidence   `json:"headline,omitempty"` //Headline evidence
	Reasons  []Evidence `json:"reasons,omitempty"`  //sub-reasons that justify why this is an issue
}

// SecurityDiagnosticsProvider interface for security diagnostics providers
type SecurityDiagnosticsProvider interface {
	//AddConsumers adds consumers to be notified by this provider when there is a new diagnostics
	AddConsumers(consumers ...SecurityDiagnosticsConsumer)
	Broadcast(diagnostic *SecurityDiagnostic)
}

// SecurityDiagnosticsConsumer is an interface with a callback to receive security diagnostics
type SecurityDiagnosticsConsumer interface {
	ReceiveDiagnostic(diagnostic *SecurityDiagnostic)
}

// DefaultSecurityDiagnosticsProvider a default implementation
type DefaultSecurityDiagnosticsProvider struct {
	consumers []SecurityDiagnosticsConsumer
}

// AddConsumers adds consumers to be notified by this provider when there is a new diagnostics
func (sdp *DefaultSecurityDiagnosticsProvider) AddConsumers(consumers ...SecurityDiagnosticsConsumer) {
	sdp.consumers = append(sdp.consumers, consumers...)
}

// Broadcast sends diagnostics to all registered consumers
func (sdp *DefaultSecurityDiagnosticsProvider) Broadcast(diagnostics *SecurityDiagnostic) {
	//ensure that the source, if provided, is converted to UTF-8
	if diagnostics.Source != nil {
		r := transform.NewReader(bytes.NewBufferString(*diagnostics.Source), unicode.UTF8.NewDecoder())
		data, err := io.ReadAll(r)
		if err != nil {
			log.Println(err)
		} else {
			*diagnostics.Source = string(data)
			data = nil
		}
	}

	for _, c := range sdp.consumers {
		c.ReceiveDiagnostic(diagnostics)
	}
}
