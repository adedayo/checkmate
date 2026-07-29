package diagnostics

import (
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//ExclusionProvider implements a exclude strategy
type ExclusionProvider interface {
	//ShouldExclude determines whether the supplied value should be excluded based on its value and the
	//path (if any) of the source file providing additional context
	ShouldExclude(pathContext, value string) bool
	ShouldExcludeHashOnPath(pathContext, hash string) bool
	ShouldExcludePath(path string) bool
	ShouldExcludeValue(value string) bool
	ShouldExcludeHash(hash string) bool
}

// ExcludeDefinition describes exclude rules
type ExcludeDefinition struct {
	//These specify regular expressions of matching strings that should be ignored as secrets anywhere they are found
	GloballyExcludedRegExs []string `yaml:"GloballyExcludedRegExs"`
	//These specify strings that should be ignored as secrets anywhere they are found
	GloballyExcludedStrings []string `yaml:"GloballyExcludedStrings"`
	//These specify SHA256 hashes that should be ignored as secrets anywhere they are found
	GloballyExcludedHashes []string `yaml:"GloballyExcludedHashes"`
	//These specify regular expressions that ignore files whose paths match
	PathExclusionRegExs []string `yaml:"PathExclusionRegExs"`
	//These specify sets of strings that should be excluded in a given file. That is filepath -> Set(strings)
	PerFileExcludedStrings map[string][]string `yaml:"PerFileExcludedStrings"`
	//These specify sets of SHA256 hashes that should be excluded in a given file. That is filepath -> Set(strings)
	PerFileExcludedHashes map[string][]string `yaml:"PerFileExcludedHashes"`
	//These specify sets of regular expressions that if matched on a path matched by the filepath key should be ignored. That is filepath_regex -> Set(regex)
	//This is a quite versatile construct and can model the four above
	PathRegexExcludedRegExs map[string][]string `yaml:"PathRegexExcludedRegex"`
}

type ExcludeContainer struct {
	ExcludeDef   *ExcludeDefinition
	Repositories []string
}
type ExcludeRequirement struct {
	What      string
	Issue     SecurityDiagnostic
	ProjectID string
}

type PolicyUpdateResult struct {
	Status    string
	NewPolicy string
}

//GenerateSampleExclusion generates a sample exclusion YAML file content with descriptions
func GenerateSampleExclusion() string {
	return `# This is a sample Exclusion YAML file to specify patterns of directories, files and values
# to exclude while searching for secrets

# Use GloballyExcludedRegExs to specify regular expressions of matching strings that should be ignored as secrets anywhere they are found
# For example (uncomment the next three lines):
#GloballyExcludedRegExs:
#    - .*keyword.* #ignore any value with the word keyword in it 
#    - .*public.*  #ignore any value with the word public in it 


# Use GloballyExcludedStrings to specify strings that should be ignored as secrets anywhere they are found
# For example (uncomment the next three lines):
#GloballyExcludedStrings:
#    - NotAPassword
#    - "Another non-password"


# Use PathExclusionRegExs to specify regular expressions that ignore files and directories, which if matched should not be scanned for secrets
PathExclusionRegExs:
#    - .*/ignore/subpath/.* # ignore files and directories which contain the subpath '/ignore/subpath/' in its name
#    - .*/README[.]md # ignore the file README.md wherever it may be found
    - .*/package-lock[.]json # ignore package-lock.json files wherever they are found
    - .*[.](html?|s?css|sass|less) # ignore webpage and stylesheet files (ending with extension .html, .htm, .css, .scss etc)

 #Use PerFileExcludedStrings to specify strings that should be excluded in a given file (indicated by its full path)
 #For example (uncomment the next six lines):
 #PerFileExcludedStrings:
 #    /home/user/myfile.txt: #file of interest
 #        - "ignore this value" # a value to ignore in the file
 #        - "another value" # another value to ignore in the file /home/user/myfile.txt
 #    "/home/user/second file.txt": #another file of interest
 #        - "not interesting" #ignore this value in the file

#PathRegexExcludedRegex is a versatile path/directory and value regular expression-based exclusion config. 
#Use it to simultaneously specify both path and value of non-interest to ignore.
#For example (uncomment the next six lines):
#PathRegexExcludedRegex:
#    .*/ignore/subpath/.*: #ignore all files and directories that have this subpath in their name
#        - .*public_key.* #ignore values that contain the phrase public_key
#        - "not secret" #ignore value 'not secret'
#    .*/keyword/directory/.*: #another path we'd like to target for ignoring certain values
#        - .*keyword.* #ignore any value with the word keyword in it in any file whose path contains subpath '/keyword/directory/'
`
}

func DefaultExclusion() ExcludeDefinition {
	return ExcludeDefinition{
		PathExclusionRegExs: []string{
			`.*/(package-lock|npm-shrinkwrap|composer)[.]json`, // ignore package-lock.json and other dependency pinning files wherever they are found
			`.*[.](html?|s?css|sass|less)`,                     // ignore webpage and stylesheet files (ending with extension .html, .htm, .css, .scss etc)
		},
	}
}

//defaultExclusionProvider contains various mechanisms for excluding false positives
type defaultExclusionProvider struct {
	*ExcludeDefinition
	globallyExcludedRegExsCompiled  []*regexp.Regexp
	pathExclusionRegExsCompiled     []*regexp.Regexp
	pathRegexExcludedRegExsCompiled map[*regexp.Regexp][]*regexp.Regexp
	repositories                    []string
}

//CompileExcludes returns a ExclusionProvider with the regular expressions already compiled
func CompileExcludes(container ExcludeContainer) (ExclusionProvider, error) {
	wl := defaultExclusionProvider{
		ExcludeDefinition: container.ExcludeDef,
		repositories:      container.Repositories,
	}
	wl.cleanSerialisationConstructs()
	err := wl.compileRegExs()
	return &wl, err
}

//MakeEmptyExcludes creates an empty default exclusion list
func MakeEmptyExcludes() ExclusionProvider {
	return &defaultExclusionProvider{
		ExcludeDefinition: &ExcludeDefinition{
			GloballyExcludedStrings: []string{},
			GloballyExcludedRegExs:  []string{},
			PathExclusionRegExs:     []string{},
			PathRegexExcludedRegExs: make(map[string][]string),
			PerFileExcludedStrings:  make(map[string][]string),
			GloballyExcludedHashes:  []string{},
			PerFileExcludedHashes:   make(map[string][]string),
		},
		globallyExcludedRegExsCompiled:  []*regexp.Regexp{},
		pathExclusionRegExsCompiled:     []*regexp.Regexp{},
		pathRegexExcludedRegExsCompiled: make(map[*regexp.Regexp][]*regexp.Regexp),
	}
}

func (wl *defaultExclusionProvider) cleanSerialisationConstructs() (err error) {
	for i, x := range wl.GloballyExcludedStrings {
		var data string
		if e := yaml.Unmarshal([]byte(x), &data); e == nil {
			wl.GloballyExcludedStrings[i] = string(data)
		} else {
			err = e
		}
	}

	wl.GloballyExcludedStrings = sort.StringSlice(wl.GloballyExcludedStrings)

	for k, v := range wl.PerFileExcludedStrings {

		after := []string{}
		for _, x := range v {
			var data string
			if e := yaml.Unmarshal([]byte(x), &data); e == nil {
				after = append(after, string(data))
			} else {
				after = append(after, x) //append erroneous unmarshalled data?
			}
		}
		after = sort.StringSlice(after)
		wl.PerFileExcludedStrings[k] = after
	}
	return
}

//compileRegExs ensures the regular expressions defined are compilable before use
func (wl *defaultExclusionProvider) compileRegExs() error {
	wl.globallyExcludedRegExsCompiled = make([]*regexp.Regexp, 0)
	bestEffortErrors := []error{}
	for _, s := range wl.GloballyExcludedRegExs {
		if re, err := regexp.Compile(s); err == nil {
			wl.globallyExcludedRegExsCompiled = append(wl.globallyExcludedRegExsCompiled, re)
		} else {
			log.Printf("Problem compiling regex: %s, Error: %s", s, err.Error())
			bestEffortErrors = append(bestEffortErrors, err)
		}
	}

	wl.pathExclusionRegExsCompiled = make([]*regexp.Regexp, 0)
	for _, s := range wl.PathExclusionRegExs {
		if re, err := regexp.Compile(s); err == nil {
			wl.pathExclusionRegExsCompiled = append(wl.pathExclusionRegExsCompiled, re)
		} else {
			log.Printf("Problem compiling regex: %s, Error: %s", s, err.Error())
			bestEffortErrors = append(bestEffortErrors, err)
		}
	}

	wl.pathRegexExcludedRegExsCompiled = make(map[*regexp.Regexp][]*regexp.Regexp)
	for p, ss := range wl.PathRegexExcludedRegExs {
		pre, err := regexp.Compile(p)
		if err != nil {
			log.Printf("Error: Compiling Regex %s, %s", p, err.Error())
			bestEffortErrors = append(bestEffortErrors, err)
			continue
		}
		srs := make([]*regexp.Regexp, 0)
		for _, s := range ss {
			sre, err := regexp.Compile(s)
			if err != nil {
				log.Printf("Problem compiling regex: %s, Error: %s", s, err.Error())
				bestEffortErrors = append(bestEffortErrors, err)
				continue
			}
			srs = append(srs, sre)
		}
		wl.pathRegexExcludedRegExsCompiled[pre] = srs
	}

	var combinedErr error

	if len(bestEffortErrors) > 0 {
		errMessages := []string{}
		for _, err := range bestEffortErrors {
			errMessages = append(errMessages, err.Error())
		}
		combinedErr = fmt.Errorf("%s", strings.Join(errMessages, "\n"))
	}

	return combinedErr
}

//ShouldExclude determines whether the supplied value should be excluded based on its value and the
//path (if any) of the source file providing additional context
func (wl *defaultExclusionProvider) ShouldExclude(pathContext, value string) bool {
	for _, s := range wl.GloballyExcludedStrings {
		if s == value {
			return true
		}
	}

	//allow policies to be portable by stripping off project repository base paths
	for _, prefix := range wl.repositories {
		pathContext = strings.TrimPrefix(pathContext, prefix)
	}

	for p, mvs := range wl.PerFileExcludedStrings {
		if p == pathContext {
			for _, mv := range mvs {
				if value == mv {
					return true
				}
			}
		}
	}

	for _, prx := range wl.pathExclusionRegExsCompiled {
		if prx.MatchString(pathContext) {
			return true
		}
	}

	for _, rx := range wl.globallyExcludedRegExsCompiled {
		if rx.MatchString(value) {
			return true
		}
	}

	for prx, rxs := range wl.pathRegexExcludedRegExsCompiled {
		if prx.MatchString(pathContext) {
			for _, rx := range rxs {
				if rx.MatchString(value) {
					return true
				}
			}
		}
	}
	return false
}

func (wl *defaultExclusionProvider) ShouldExcludeHashOnPath(pathContext, hash string) bool {

	for _, s := range wl.GloballyExcludedHashes {
		if s == hash {
			return true
		}
	}

	//allow policies to be portable by stripping off project repository base paths
	for _, prefix := range wl.repositories {
		pathContext = strings.TrimPrefix(pathContext, prefix)
	}

	for p, mvs := range wl.PerFileExcludedHashes {
		if p == pathContext {
			for _, mv := range mvs {
				if hash == mv {
					return true
				}
			}
		}
	}

	return false
}

func (wl *defaultExclusionProvider) ShouldExcludeHash(hash string) bool {
	for _, s := range wl.GloballyExcludedHashes {
		if s == hash {
			return true
		}
	}
	return false
}

//ShouldExcludePath determines whether the path should be excluded from analysis
func (wl *defaultExclusionProvider) ShouldExcludePath(pathContext string) bool {

	for _, prx := range wl.pathExclusionRegExsCompiled {
		if prx.MatchString(pathContext) {
			return true
		}
	}

	return false
}

//ShouldExcludeValue determines whether the value should be excluded from results
func (wl *defaultExclusionProvider) ShouldExcludeValue(value string) bool {

	for _, s := range wl.GloballyExcludedStrings {
		if s == value {
			return true
		}
	}

	for _, rx := range wl.globallyExcludedRegExsCompiled {
		if rx.MatchString(value) {
			return true
		}
	}

	return false
}
