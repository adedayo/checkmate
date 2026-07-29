package diagnostics

type Progress struct {
	ProjectID   string
	ScanID      string
	Position    int64 //how many files processed so far
	Total       int64 //total number of files
	CurrentFile string
}
