package secrets

import (
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

var (
	descHardCodedSecretAssignment = "Hard-coded secret assignment"
	descVarSecret                 = "Variable name suggests it is a secret"
	descEncodedSecret             = "Value looks suspiciously like an encoded secret (e.g. Base64 or Hex encoded)"
	descSecretUnbrokenString      = "Unbroken string may be a secret"
	// descConstantAssignment         = "Constant assignment to a variable name that suggests it is a secret"
	descHardCodedSecret = "Hard-coded secret"
	// descDefaultSecret              = "Default or common secret value"
	descCommonSecret               = "Value contains or appears to be a common credential"
	descSuspiciousSecret           = "Value looks suspiciously like a secret"
	descHighEntropy                = "Value has a high entropy, may be a secret"
	descNotSecret                  = "Value does not appear to be a secret"
	unusualPasswordStartCharacters = `<>&^%?#({|/`

	assignmentProviderID          = "SecretAssignment"
	confAssignmentProviderID      = "ConfSecretAssignment"
	cppAssignmentProviderID       = "CPPSecretAssignment"
	longTagValueProviderID        = "LongOrSuspiciousSecretInXML"
	xmlAssignmentProviderID       = "SecretAssignmentInXML"
	secretTagProviderID           = "SuspiciousOrCommonSecretInXML"
	jsonAssignmentProviderID      = "JSONSecretAssignment"
	yamlAssignmentProviderID      = "YAMLSecretAssignment"
	arrowAssignmentProviderID     = "ArrowSecretAssignment"
	defineAssignmentProviderID    = "DefineSecretAssignment"
	tagAssignmentProviderID       = "ElementSecretAssignment"
	attributeAssignmentProviderID = "AttributeSecretAssignment"
	longStringProviderID          = "LongOrSuspiciousSecretString"
	secretStringProviderID        = "SuspiciousOrCommonSecretString"
	recognisedFiles               = map[string]bool{".java": true, ".scala": true, ".kt": true, ".go": true, ".c": true,
		".cpp": true, ".cc": true, ".c++": true, ".h++": true, ".hh": true, ".hpp": true, ".xml": true,
		".json": true, ".yaml": true, ".yml": true, ".rb": true, ".erb": true, ".conf": true}
)

// GetFinderForFileType returns the appropriate MatchProvider based on the file type hint
func GetFinderForFileType(fileType string, options SecretSearchOptions) MatchProvider {
	switch strings.ToLower(fileType) {
	case ".java", ".scala", ".kt", ".go":
		return NewJavaFinder(options)
	case ".c", ".cpp", ".cc", ".c++", ".h++", ".hh", ".hpp", ".hxx":
		return NewCPPSecretsFinders(options)
	case ".xml":
		return NewXMLSecretsFinders(options)
	// case ".json":
	// 	return NewJSONSecretsFinders(options)
	case ".yaml", ".yml", ".json":
		return NewYamlSecretsFinders(options)
	case ".rb":
		return NewRubySecretsFinders(options)
	case ".erb":
		return NewERubySecretsFinders(options)
	case ".conf":
		return NewConfigurationSecretsFinder(options)
	default:
		return defaultFinder(options)
	}
}

func defaultFinder(options SecretSearchOptions) MatchProvider {
	return &defaultMatchProvider{
		finders: append(makeVendorSecretsFinders(options),
			[]common.ResourceToSecurityDiagnostics{
				makeAssignmentFinder(assignmentProviderID, secretAssignment, options),
				makeSecretStringFinder(secretStringProviderID, secretStrings, options),
				makeSecretStringFinder(longStringProviderID, longStrings, options),
				makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment, options),
				makeAssignmentFinder(arrowAssignmentProviderID, arrowQuoteLeft, options),
				makeAssignmentFinder(arrowAssignmentProviderID, arrowNoQuoteLeft, options),
			}...),
	}
}

// NewJavaFinder provides secret detection in Java-like programming languages
func NewJavaFinder(options SecretSearchOptions) MatchProvider {
	return &defaultMatchProvider{
		finders: append(makeVendorSecretsFinders(options),
			[]common.ResourceToSecurityDiagnostics{
				makeAssignmentFinder(assignmentProviderID, secretAssignment, options),
				makeSecretStringFinder(secretStringProviderID, secretStrings, options),
				makeSecretStringFinder(longStringProviderID, longStrings, options),
			}...),
	}
}

// MatchProvider provides regular expressions and other facilities for locating secrets in source data and resources
type MatchProvider interface {
	// common.exclusionProvider
	GetFinders() []common.ResourceToSecurityDiagnostics
}

// RegexFinder provides secret detection using regular expressions
type RegexFinder struct {
	diagnostics.DefaultSecurityDiagnosticsProvider
	res      []*regexp.Regexp
	regexIDs []string //used to map each regex above to a potentially unique ID.
	//lineIndex and rif are per-file state, supplied by the resource
	//multiplexer for each file rather than captured at construction. Keeping
	//them out of the constructor is what allows a finder to be built once and
	//reused across many files.
	lineIndex     *util.LineIndex
	rif           util.RepositoryIndexedFile
	providerID    string
	provideSource bool
}

// GetRegularExpressions returns the underlying compiled regular expressions
func (finder RegexFinder) GetRegularExpressions() []*regexp.Regexp {
	return finder.res
}

// Consume allows a source processor receive `source` data streamed in "chunks", with `startIndex` indicating the
// character location of the first character in the stream
func (finder *RegexFinder) Consume(startIndex int64, source string) {
}

// SetLineIndex allows this source consumer to keep track of `code.Position`
func (finder *RegexFinder) SetLineIndex(li *util.LineIndex) {
	finder.lineIndex = li
}

// SetRepositoryFile supplies the per-file context (path and the index of the
// scan root it was found under) for the file about to be consumed.
func (finder *RegexFinder) SetRepositoryFile(rif util.RepositoryIndexedFile) {
	finder.rif = rif
}

// End is used to signal to the consumer that the source stream has ended
func (finder *RegexFinder) End() {

}

// ShouldProvideSourceInDiagnostics toggles whether source evidence should be provided with diagnostics, defaults to false
func (finder *RegexFinder) ShouldProvideSourceInDiagnostics(provideSource bool) {
	finder.provideSource = provideSource
}

type defaultMatchProvider struct {
	finders []common.ResourceToSecurityDiagnostics
}

func (dmp defaultMatchProvider) GetFinders() []common.ResourceToSecurityDiagnostics {
	return dmp.finders
}

// func (dmp defaultMatchProvider) ShouldExclude(pathContext, value string) bool {
// 	for _, finder := range dmp.GetFinders() {
// 		if finder.ShouldExclude(pathContext, value) {
// 			return true
// 		}
// 	}
// 	return false
// }

// NewConfigurationSecretsFinder is a `MatchProvider` for finding secrets in configuration `.conf` files
func NewConfigurationSecretsFinder(options SecretSearchOptions) MatchProvider {
	return &defaultMatchProvider{
		finders: append(makeVendorSecretsFinders(options),
			[]common.ResourceToSecurityDiagnostics{
				makeAssignmentFinder(confAssignmentProviderID, confAssignment, options),
				makeAssignmentFinder(assignmentProviderID, secretAssignment, options),
				makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment, options),
				makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool, options),
				makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, options),
				makeSecretStringFinder(secretStringProviderID, secretStrings, options),
				makeSecretStringFinder(longStringProviderID, longStrings, options),
			}...),
	}
}

// NewCPPSecretsFinders is a `MatchProvider` for finding secrets in files with C++-like content
func NewCPPSecretsFinders(options SecretSearchOptions) MatchProvider {
	return &defaultMatchProvider{
		finders: append(makeVendorSecretsFinders(options),
			[]common.ResourceToSecurityDiagnostics{
				makeAssignmentFinder(cppAssignmentProviderID, secretCPPAssignment, options),
				makeAssignmentFinder(defineAssignmentProviderID, secretDefine, options),
				makeSecretStringFinder(secretStringProviderID, secretStrings, options),
				makeSecretStringFinder(longStringProviderID, longStrings, options),
			}...),
	}
}

type idRegexPair struct {
	id    string
	regex *regexp.Regexp
}

// NewXMLSecretsFinders is a `MatchProvider` for finding secrets in files with XML content
func NewXMLSecretsFinders(options SecretSearchOptions) MatchProvider {
	return &defaultMatchProvider{
		finders: append(makeVendorSecretsFinders(options),
			[]common.ResourceToSecurityDiagnostics{
				makeXMLSecretsFinder([]idRegexPair{
					{xmlAssignmentProviderID, secretAssignment},
					{xmlAssignmentProviderID, yamlAssignment},
					{xmlAssignmentProviderID, arrowNoQuoteLeft},
					{xmlAssignmentProviderID, arrowQuoteLeft},
					{secretTagProviderID, secretUnquotedTextRegex},
					{longTagValueProviderID, longUnquotedTextRegex},
					{secretStringProviderID, secretStrings},
					{longStringProviderID, longStrings},
				}, options),
			}...),
	}
}

//NewJSONSecretsFinders is a `MatchProvider` for finding secrets in files with JSON content
// func NewJSONSecretsFinders(options SecretSearchOptions) MatchProvider {
// 	return &defaultMatchProvider{
// 		finders: append(makeVendorSecretsFinders(options,rif), []common.ResourceToSecurityDiagnostics{
// 			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, options),
// 			makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool, options),
// 			makeSecretStringFinder(longStringProviderID, longStrings, options),
// 		}...),
// 	}
// }

// NewRubySecretsFinders is a `MatchProvider` for finding secrets in files with Ruby content
func NewRubySecretsFinders(options SecretSearchOptions) MatchProvider {
	return &defaultMatchProvider{
		finders: append(makeVendorSecretsFinders(options),
			[]common.ResourceToSecurityDiagnostics{
				makeAssignmentFinder(tagAssignmentProviderID, secretTags, options),
				makeAssignmentFinder(assignmentProviderID, secretAssignment, options),
				makeAssignmentFinder(longTagValueProviderID, longTagValues, options),
				makeAssignmentFinder(secretTagProviderID, secretTagValues, options),
				makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment, options),
				makeSecretStringFinder(secretStringProviderID, secretStrings, options),
				makeSecretStringFinder(longStringProviderID, longStrings, options),
			}...),
	}
}

// NewERubySecretsFinders is a `MatchProvider` for finding secrets in files with ERuby content
func NewERubySecretsFinders(options SecretSearchOptions) MatchProvider {
	return &defaultMatchProvider{
		finders: append(makeVendorSecretsFinders(options),
			[]common.ResourceToSecurityDiagnostics{
				makeAssignmentFinder(tagAssignmentProviderID, secretTags, options),
				makeAssignmentFinder(assignmentProviderID, secretAssignment, options),
				makeAssignmentFinder(longTagValueProviderID, longTagValues, options),
				makeAssignmentFinder(secretTagProviderID, secretTagValues, options),
				makeSecretStringFinder(secretStringProviderID, secretStrings, options),
				makeSecretStringFinder(longStringProviderID, longStrings, options),
				makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentNumOrBool, options),
				makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment, options),
				makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, options),
			}...),
	}
}

// NewYamlSecretsFinders is a `MatchProvider` for finding secrets in files with YAML content
func NewYamlSecretsFinders(options SecretSearchOptions) MatchProvider {
	return &defaultMatchProvider{
		finders: append(makeVendorSecretsFinders(options),
			[]common.ResourceToSecurityDiagnostics{
				makeAssignmentFinder(yamlAssignmentProviderID, yamlAssignment, options),
				makeAssignmentFinder(jsonAssignmentProviderID, jsonAssignmentString, options),
				makeSecretStringFinder(secretStringProviderID, secretStrings, options),
				makeSecretStringFinder(longStringProviderID, longStrings, options),
			}...),
	}
}

func makeXMLSecretsFinder(stringRegexes []idRegexPair,
	options SecretSearchOptions) *xmlSecretFinder {
	sxml := xmlSecretFinder{
		secretFinder: secretFinder{
			ExclusionProvider: options.Exclusions,
			options:           options,
		},
	}

	for _, pair := range stringRegexes {
		sxml.regexIDs = append(sxml.regexIDs, pair.id)
		sxml.res = append(sxml.res, pair.regex)
	}

	return &sxml
}

func makeAssignmentFinder(providerID string, re *regexp.Regexp, options SecretSearchOptions) *assignmentFinder {
	sa := assignmentFinder{
		secretFinder{
			ExclusionProvider: options.Exclusions,
			options:           options,
		},
	}
	sa.providerID = providerID
	sa.res = []*regexp.Regexp{re}
	return &sa
}

func makeSecretStringFinder(providerID string, re *regexp.Regexp, options SecretSearchOptions) *secretStringFinder {
	sf := secretStringFinder{
		secretFinder{
			ExclusionProvider: options.Exclusions,
			options:           options,
		},
	}

	sf.providerID = providerID
	sf.res = []*regexp.Regexp{re}
	return &sf
}

type secretFinder struct {
	RegexFinder
	diagnostics.DefaultSecurityDiagnosticsProvider
	diagnostics.ExclusionProvider
	options SecretSearchOptions
	// gate and gateIndex implement prefilter rule skipping.
	//
	// Both are per-worker, not per-file: the gate is owned by the ScanContext
	// that built this finder and is refreshed for each file before any finder
	// runs. gateIndex is -1 for every finder that is not a gated vendor rule,
	// which makes gating a no-op for the generic assignment/string finders.
	gate      *ruleGate
	gateIndex int
}

// skipRule reports whether this finder can be skipped for the current content
// because the prefilter proved none of its literals are present.
func (sf *secretFinder) skipRule() bool {
	return sf.gate != nil && !sf.gate.allows(sf.gateIndex)
}

// attachGate wires the worker's prefilter into this finder.
//
// Every finder embedding secretFinder gets the gate, not only the gated vendor
// rules. A generic assignment or string finder still resolves to gateIndex -1
// and therefore always runs — but it also *classifies* the values it finds
// through detectSecret, and that classification evaluates the whole vendor
// rule set. Withholding the gate from those finders is what left the most
// expensive path in the engine ungated after Phase 4.
func (sf *secretFinder) attachGate(gate *ruleGate) {
	sf.gate = gate
	sf.gateIndex = gate.indexOf(sf.providerID)
}

// gatedFinder is implemented by every finder embedding secretFinder.
type gatedFinder interface {
	attachGate(*ruleGate)
}

type assignmentFinder struct {
	secretFinder
}

func computeHash(shouldCompute bool, value string) *string {
	if shouldCompute {
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
		return &hash
	}
	return nil
}

func computeFileHash(shouldCompute bool, path string) *string {
	if shouldCompute {
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer func() {
			_ = f.Close()
		}()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil
		}
		hash := fmt.Sprintf("%x", h.Sum(nil))
		return &hash
	}
	return nil
}

func (sa *assignmentFinder) Consume(startIndex int64, source string) {
	for _, re := range sa.GetRegularExpressions() {
		matches := re.FindAllStringSubmatchIndex(source, -1)
		for _, match := range matches {
			if len(match) == 6 { //we are expecting 6 elements
				processAssignment(match, sa.providerID, source, startIndex, sa.secretFinder)
			}
		}
	}
}

func (sa *assignmentFinder) ConsumePath(path util.RepositoryIndexedFile) {
}

// trimQuotes attempts to remove balanced quotes around a piece of string
// returns the trimmed text and the number of characters trimmed from the prefix
func trimQuotes(text string) (string, int) {
	text = strings.TrimSpace(text)
	count := 0
	text, c := balancedTrim(text, '`')
	count += c
	text, c = balancedTrim(text, []byte(`'`)[0])
	count += c
	text, c = balancedTrim(text, '"')
	count += c
	//for tripple quoted strings deal with the next pair of quotes
	if len(text) > 3 && strings.HasPrefix(text, `""`) && strings.HasSuffix(text, `""`) {
		text = strings.TrimPrefix(text, `""`)
		text = strings.TrimSuffix(text, `""`)
		count += 2
	}
	return text, count
}

func balancedTrim(text string, quote byte) (string, int) {
	trimmed := text
	count := 0
	if len(text) > 1 && text[0] == quote && text[len(text)-1] == quote {
		trimmed = text[1 : len(text)-1]
		count++
	}
	return trimmed, count
}

// func isQuote(q rune) bool {
// 	return strings.ContainsRune("`'"+`"`, q)
// }

type secretStringFinder struct {
	secretFinder
}

func (sf *secretStringFinder) Consume(startIndex int64, source string) {
	// The prefilter has already established that none of this rule's mandatory
	// literals occur in `source`, so the regex cannot match. This is where the
	// scan's dominant cost disappears: on ordinary source files it skips ~93%
	// of the vendor rule set.
	if sf.skipRule() {
		return
	}
	for _, re := range sf.GetRegularExpressions() {
		matches := re.FindAllStringSubmatchIndex(source, -1)
		for _, match := range matches {
			if len(match) == 4 && !containsWhitespace(source[match[0]:match[1]]) {
				processString(match, sf.providerID, source, startIndex, sf.secretFinder)
			}
		}
	}

}

func (sf *secretStringFinder) ConsumePath(path util.RepositoryIndexedFile) {

}

type xmlSecretFinder struct {
	secretFinder
	// source accumulates the file content delivered through Consume, so the
	// XML parse can run over memory the engine has already read.
	source strings.Builder
}

func (xf *xmlSecretFinder) Consume(startIndex int64, source string) {
	// The XML parse happens in ConsumePath, once the whole document has
	// arrived. Retaining the content here is what lets it avoid re-reading the
	// file from disk.
	xf.source.WriteString(source)
}

func (xf *xmlSecretFinder) ConsumePath(rif util.RepositoryIndexedFile) {

	content := xf.source.String()
	// Reset immediately: this finder is reused across files, and content left
	// behind would be parsed again as part of the next document.
	xf.source.Reset()

	if content == "" {
		return
	}

	// Two independent readers over the same in-memory content: one for the
	// decoder, one for seeking to positions.
	//
	// This previously opened the file from disk twice, on top of the read the
	// engine had already performed to stream the content into Consume — three
	// full reads of every XML file, two of them redundant. The content is
	// already in hand, so both readers are now views onto it.
	file := strings.NewReader(content)
	scan := strings.NewReader(content)

	decoder := xml.NewDecoder(file)
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose
	decoder.Entity = xml.HTMLEntity

	//to push and pop xml elements as we parse the document
	var stack stack

	for {
		t, _ := decoder.RawToken()
		if t == nil || t == io.EOF {
			break
		}

		switch se := t.(type) {
		case xml.StartElement:
			stack.push(se.Name.Local)
			var elementOffSet int64
			var attributes string
			if len(se.Attr) > 0 {
				elementOffSet = findElementOffset(scan, decoder.InputOffset(), se.Name.Local)
				buffSize := int(decoder.InputOffset() - elementOffSet)
				buff := make([]byte, buffSize)
				_, _ = scan.Seek(elementOffSet, io.SeekStart)
				_, err := scan.Read(buff)
				if err != nil {
					log.Printf("Error %s\n", err.Error())
				}
				attributes = string(buff)
			}
			for _, attr := range se.Attr {
				offset := decoder.InputOffset()
				if index := strings.Index(attributes, attr.Name.Local); index != -1 {
					offset = elementOffSet + int64(index)
				}
				processXMLAssignment(attr.Name.Local, attr.Value, offset, false, xf, scan)
			}
		case xml.CharData: //CDATA <![CDATA[ some CDATA content ]]>
			//- decoder also sends raw element values e.g. <el>element value</el> as CharData
			cdata := string(se)
			if strings.TrimSpace(cdata) == "" {
				continue
			}
			isChar := isCharData(scan, decoder.InputOffset())
			if !isChar {
				//deal with element value
				if el, e := stack.peek(); e == nil {
					processXMLAssignment(el, cdata, decoder.InputOffset()-int64(len(cdata)), true, xf, scan)
				}
			} else {
				//proper CDATA
				processXMLStrings(cdata, decoder.InputOffset()-int64(len(cdata)+3 /**the 3 ]]> chars */), xf)
			}
		case xml.Comment: // <!-- comments in xml -->
			comment := string(se)
			processXMLStrings(comment, decoder.InputOffset()-int64(len(comment)+3 /**the 3 --> chars */), xf)
		case xml.EndElement:
			if _, e := stack.pop(); e != nil {
				log.Printf("%s", e.Error())
			}
		default:
		}
	}
}

// try and locate the offset of the <element  (the position of the letter t in <element )
// this may fail, in which case we will just simply return the original offset passed to the function
func findElementOffset(file io.ReadSeeker, offset int64, element string) int64 {
	length := 2 * len(element) // we are going to search backwards reading twice (arbitrary) the length of the attribute
	if length == 0 {           //degenerate case
		return offset
	}
	maxReverseDistance := 10240 // beyond which we will give up
	stopString := fmt.Sprintf("<%s", element)
	for traversed := length; traversed <= maxReverseDistance; traversed += length {
		buff := make([]byte, traversed)
		start := offset - int64(traversed)
		if _, err := file.Seek(start, io.SeekStart); err == nil {
			_, err = file.Read(buff)
			if err != nil {
				break
			}
			if index := strings.Index(string(buff), stopString); index != -1 {
				// found the beginning
				return start + int64(index+len(stopString))
			}
		} else {
			break
		}
	}

	return offset
}

func processXMLStrings(data string, sourceIndex int64, finder *xmlSecretFinder) {
	for i, re := range finder.res {
		providerID := finder.regexIDs[i]
		findXMLStringSecret(data, sourceIndex, providerID, re, finder)
	}
}

func processAssignment(match []int, providerID, source string, startIndex int64,
	sf secretFinder) {
	if len(match) == 6 { //we are expecting 6 elements
		lhsStart := int64(match[2])
		variable := strings.TrimSpace(strings.ToLower(source[lhsStart:match[3]]))

		//check if variable contains newline or space => in which case it's most likely an FP
		if strings.Contains(variable, "\n") || containsWhitespace(variable) {
			return
		}

		end := int64(match[1])
		start2 := lhsStart
		if start2 > 0 {
			start2 -= 1
		}
		s := source[start2:end]
		if sf.ShouldExcludeValue(s) {
			return
		}
		rhsStart := int64(match[4]) //beginning of assigned value
		assignedVal := source[rhsStart:end]
		assignedVal, count := trimQuotes(assignedVal)
		rhsStart += int64(count)
		rhsEnd := rhsStart + int64(len(assignedVal))
		evidence := detectSecret(secretContext{secret: assignedVal, higherConfidenceContext: true, gate: sf.gate})

		// log.Printf("(%s) Variable: %s <=> %s\n", providerID, variable, assignedVal)
		// log.Printf("(%s) Evidence: %#v \n", providerID, evidence)

		if strings.Contains(variable, "passphrase") {
			//special "passphrase" case:
			//if the assigned variable is a passphrase bypass any result of the assigned value
			evidence.Description = descHardCodedSecret
			evidence.Confidence = diagnostics.High
		} else if evidence.Description == descNotSecret && evidence.Confidence == diagnostics.High {
			//for high-confidence non-secrets ignore the result even if variable name suggests so
			return
		}

		codeStart := startIndex + lhsStart
		codeEnd := startIndex + end
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
				Start: sf.lineIndex.GetPositionFromCharacterIndex(codeStart),
				End:   sf.lineIndex.GetPositionFromCharacterIndex(codeEnd),
			},
			RawRange: diagnostics.CharRange{
				StartIndex: codeStart,
				EndIndex:   codeEnd,
			},
			HighlightRange: code.Range{
				Start: sf.lineIndex.GetPositionFromCharacterIndex(startIndex + rhsStart - 1),
				End:   sf.lineIndex.GetPositionFromCharacterIndex(startIndex + rhsEnd - 1),
			},
			ProviderID:      &providerID,
			Excluded:        sf.ShouldExcludeValue(assignedVal),
			SHA256:          computeHash(sf.options.CalculateChecksum, assignedVal),
			RepositoryIndex: sf.rif.RepositoryIndex,
		}
		if diagnostic.Justification.Reasons[1].Confidence > diagnostics.Low {
			diagnostic.Justification.Headline.Confidence = diagnostics.High
		}
		if diagnostic.Justification.Reasons[1].Description == descNotSecret &&
			diagnostic.Justification.Headline.Confidence > diagnostics.Medium {
			diagnostic.Justification.Headline.Confidence = diagnostics.Medium
		}

		if sf.provideSource {
			diagnostic.Source = &s
		}

		if !sf.options.CalculateChecksum || !sf.ShouldExcludeHash(*diagnostic.SHA256) {
			sf.Broadcast(&diagnostic)
		}

	}
}

type byConfidence []diagnostics.Evidence

func (a byConfidence) Len() int           { return len(a) }
func (a byConfidence) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byConfidence) Less(i, j int) bool { return a[i].Confidence > a[j].Confidence }

func processString(match []int, providerID, source string, startIndex int64,
	sf secretFinder) {
	start := int64(match[0])
	end := int64(match[1])
	s := source[start:end]
	if sf.ShouldExcludeValue(s) {
		return
	}
	value := source[start:end]
	value, count := trimQuotes(value)
	stringStart := start + int64(count)
	stringEnd := stringStart + int64(len(value))

	evidence := detectSecret(secretContext{secret: value, gate: sf.gate})
	if evidence.Description == descNotSecret && evidence.Confidence == diagnostics.High {
		return //skip high confidence non-secrets
	}

	codeStart := startIndex + start
	codeEnd := startIndex + end

	reasons := []diagnostics.Evidence{
		{
			Description: descSecretUnbrokenString,
			Confidence:  diagnostics.Medium,
		},
		evidence}

	sort.Sort(byConfidence(reasons))

	diagnostic := diagnostics.SecurityDiagnostic{
		Justification: diagnostics.Justification{
			Headline: reasons[0],
			Reasons:  reasons,
		},
		Range: code.Range{
			Start: sf.lineIndex.GetPositionFromCharacterIndex(codeStart),
			End:   sf.lineIndex.GetPositionFromCharacterIndex(codeEnd),
		},
		RawRange: diagnostics.CharRange{
			StartIndex: codeStart,
			EndIndex:   codeEnd,
		},
		HighlightRange: code.Range{
			Start: sf.lineIndex.GetPositionFromCharacterIndex(startIndex + stringStart - 1),
			End:   sf.lineIndex.GetPositionFromCharacterIndex(startIndex + stringEnd - 1),
		},
		ProviderID:      &providerID,
		Excluded:        sf.ShouldExcludeValue(value),
		SHA256:          computeHash(sf.options.CalculateChecksum, value),
		RepositoryIndex: sf.rif.RepositoryIndex,
	}
	if diagnostic.Justification.Reasons[1].Confidence == diagnostics.High {
		diagnostic.Justification.Headline.Confidence = diagnostics.High
	}
	//set the headline confidence to the lower confidence if we are dealing just with unbroken string
	if diagnostic.Justification.Headline.Description == descSecretUnbrokenString &&
		diagnostic.Justification.Reasons[1].Confidence < diagnostics.Medium {
		diagnostic.Justification.Headline.Confidence = diagnostic.Justification.Reasons[1].Confidence

	}

	if sf.provideSource {
		diagnostic.Source = &s
	}
	if !sf.options.CalculateChecksum || !sf.ShouldExcludeHash(*diagnostic.SHA256) {
		sf.Broadcast(&diagnostic)
	}

}

func findXMLStringSecret(source string, startIndex int64, providerID string, re *regexp.Regexp, sf *xmlSecretFinder) {
	if strings.TrimSpace(source) == "" {
		return
	}
	matches := re.FindAllStringSubmatchIndex(source, -1)
	for _, match := range matches {
		if len(match) == 6 { //assignment match signature
			processAssignment(match, providerID, source, startIndex, sf.secretFinder)
		} else if len(match) == 4 && !containsWhitespace(source[match[0]:match[1]]) {
			processString(match, providerID, source, startIndex, sf.secretFinder)
		}
	}
}

// checks whether the current event is true CharData by checking for the closing marker ]]>
func isCharData(file io.ReadSeeker, start int64) bool {
	if start > 3 {
		if _, err := file.Seek(start-3, io.SeekStart); err != nil {
			return false
		}
		data := make([]byte, 3)
		if n, err := file.Read(data); n == 3 && err == nil && string(data) == "]]>" {
			return true
		}
	}
	return false
}

// used for XML elements and attribute "assignments"
func processXMLAssignment(variable, assignedVal string, sourceIndex int64, isElement bool, finder *xmlSecretFinder,
	scan io.ReadSeeker) {
	start := sourceIndex - int64(1) //peg the startindex back by 1 char
	end := start + int64(len(assignedVal))
	if !isElement {
		end = start + int64(len(variable)+len(assignedVal)+3) // 3 chars to account for = and ""
	}
	variable = strings.ToLower(variable)
	rawAssigned := assignedVal
	assignedVal, _ = trimQuotes(assignedVal)
	// stringStart := start + int64(count)
	// stringEnd := stringStart + int64(len(assignedVal))
	assignedVal = strings.TrimSpace(assignedVal)

	if isElement && assignedVal == "" {
		//ignore xml elements that are not pure value e.g. <secret><otherElement></otherElement></secret>
		//we are interested in values such as <secret>some value</secret>
		return
	}
	if secretVarCompile.MatchString(variable) {
		evidence := detectSecret(secretContext{secret: assignedVal, higherConfidenceContext: true, gate: finder.gate})
		if strings.Contains(variable, "passphrase") {
			//special "passphrase" case:
			//if the assigned variable is a passphrase bypass any result of the assigned value
			evidence.Description = descHardCodedSecret
			evidence.Confidence = diagnostics.High
		}

		providerID := tagAssignmentProviderID
		if !isElement {
			providerID = attributeAssignmentProviderID
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
				Start: finder.lineIndex.GetPositionFromCharacterIndex(start + 1),
				End:   finder.lineIndex.GetPositionFromCharacterIndex(end),
			},
			RawRange: diagnostics.CharRange{
				StartIndex: start + 1,
				EndIndex:   end,
			},
			HighlightRange: code.Range{ //TODO the highlighted range is the same as the total range, fix
				Start: finder.lineIndex.GetPositionFromCharacterIndex(start + 1),
				End:   finder.lineIndex.GetPositionFromCharacterIndex(end),
			},
			ProviderID:      &providerID,
			Excluded:        finder.ShouldExcludeValue(assignedVal),
			SHA256:          computeHash(finder.options.CalculateChecksum, assignedVal),
			RepositoryIndex: finder.rif.RepositoryIndex,
		}
		if diagnostic.Justification.Reasons[1].Confidence > diagnostics.Low {
			diagnostic.Justification.Headline.Confidence = diagnostics.High
		}
		if diagnostic.Justification.Reasons[1].Description == descNotSecret &&
			diagnostic.Justification.Headline.Confidence > diagnostics.Medium {
			diagnostic.Justification.Headline.Confidence = diagnostics.Medium
		}
		if finder.provideSource {
			// s := fmt.Sprintf(`%s="%s"`, variable, assignedVal)
			// if isElement {
			// 	s = fmt.Sprintf(`%s > %s`, variable, assignedVal)
			// }
			buff := make([]byte, end-start+1)
			_, _ = scan.Seek(start, io.SeekStart)
			_, _ = scan.Read(buff)
			s := string(buff)
			diagnostic.Source = &s
		}
		if !finder.options.CalculateChecksum || !finder.ShouldExcludeHash(*diagnostic.SHA256) {
			finder.Broadcast(&diagnostic)
		}

	} else {
		//deal with case where element or attribute name does not suggest value is a secret
		processXMLStrings(rawAssigned, sourceIndex, finder)
	}
}
