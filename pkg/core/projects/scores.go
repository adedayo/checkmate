package projects

import "time"

type Score struct {
	Grade      string             // A+ -> F
	Metric     float32            //100% -> 0%
	TimeStamp  time.Time          //when the scan was completed
	SubMetrics map[string]float32 // use this to record arbitrary numeric scores, even time series of trends etc.
}
