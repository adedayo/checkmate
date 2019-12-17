package diagnostics

import (
	"fmt"
	"regexp"
)

//DefaultWhitelistProvider contains various mechanisms for excluding false positives
type DefaultWhitelistProvider struct {
	//These specify regular expressions of matching strings that should be ignored as secrets anywhere they are found
	GloballyExcludedRegExs         []string `yaml:"GloballyExcludedRegExs,omitempty"`
	globallyExcludedRegExsCompiled []*regexp.Regexp
	//These specify strings that should be ignored as secrets anywhere they are found
	GloballyExcludedStrings []string `yaml:"GloballyExcludedStrings,omitempty"`
	//These specify regular expression that ignore files whose paths match
	PathExclusionRegExs         []string `yaml:"PathExclusionRegExs,omitempty"`
	pathExclusionRegExsCompiled []*regexp.Regexp
	//These specify sets of strings that should be excluded in a given file. That is filepath -> Set(strings)
	PerFileExcludedStrings map[string]map[string]struct{} `yaml:"PerFileExcludedStrings,omitempty"`
}

//MakeWhitelists creates a whitelist from parameters
func MakeWhitelists(globallyExcludedString, globallyExcludedRegex, pathExclusionRegex []string, perFile map[string]map[string]struct{}) DefaultWhitelistProvider {
	wl := DefaultWhitelistProvider{
		GloballyExcludedStrings: globallyExcludedString,
		GloballyExcludedRegExs:  globallyExcludedRegex,
		PathExclusionRegExs:     pathExclusionRegex,
		PerFileExcludedStrings:  perFile,
	}
	fmt.Printf("\n\nBefore Compile %#v\n\n", wl)
	wl.CompileRegExs()
	fmt.Printf("\n\nAfter Compile %#v\n\n", wl)
	return wl
}

//MakeEmptyWhitelists creates an empty default whitelist
func MakeEmptyWhitelists() DefaultWhitelistProvider {
	return DefaultWhitelistProvider{}
}

//CompileRegExs ensures the regular expressions defined are compiled before use
func (wl *DefaultWhitelistProvider) CompileRegExs() {
	for _, s := range wl.GloballyExcludedRegExs {
		if re, err := regexp.Compile(s); err == nil {
			wl.globallyExcludedRegExsCompiled = append(wl.globallyExcludedRegExsCompiled, re)
		}
	}

	for _, s := range wl.PathExclusionRegExs {
		if re, err := regexp.Compile(s); err == nil {
			wl.pathExclusionRegExsCompiled = append(wl.pathExclusionRegExsCompiled, re)
		}
	}
}

//ShouldWhitelist determines whether the supplied value should be whitelisted based on its value and the
//path (if any) of the source file providing additional context
func (wl *DefaultWhitelistProvider) ShouldWhitelist(pathContext, value string) bool {
	for _, s := range wl.GloballyExcludedStrings {
		if s == value {
			return true
		}
	}

	for p, mvs := range wl.PerFileExcludedStrings {
		if p == pathContext {
			if _, present := mvs[value]; present {
				return true
			}
		}
	}

	for _, rx := range wl.globallyExcludedRegExsCompiled {
		if rx.MatchString(value) {
			return true
		}
	}

	for _, prx := range wl.pathExclusionRegExsCompiled {
		if prx.MatchString(pathContext) {
			return true
		}
	}

	return false
}

//ShouldWhitelistPath determines whether the path should be excluded from analysis
func (wl *DefaultWhitelistProvider) ShouldWhitelistPath(pathContext string) bool {

	for _, prx := range wl.pathExclusionRegExsCompiled {
		if prx.MatchString(pathContext) {
			return true
		}
	}

	return false
}

//ShouldWhitelistValue determines whether the value should be excluded from results
func (wl *DefaultWhitelistProvider) ShouldWhitelistValue(value string) bool {

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

//WhitelistProvider implements a whitelist strategy
type WhitelistProvider interface {
	//ShouldWhitelist determines whether the supplied value should be whitelisted based on its value and the
	//path (if any) of the source file providing additional context
	ShouldWhitelist(pathContext, value string) bool
	ShouldWhitelistPath(path string) bool
	ShouldWhitelistValue(value string) bool
}
