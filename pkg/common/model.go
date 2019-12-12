package common

//DataToScan represents data to be inspected for possible secrets embedded along with
//hints and configurations about the nature of the data and the scanning sensitivity
type DataToScan struct {
	//Source is the textual data to be scanned for secrets
	Source string `json:"source"`
	//SourceType is a hint as to the type of the source e.g .java, .xml, .yaml, .json, .rb, etc
	SourceType string `json:"source_type"`
	//Base64 is an optional flag that is used to indicate whether the text in `Source` is Base64-encoded
	Base64 bool `json:"base64,omitempty"`
}
