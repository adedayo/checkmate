package projects

import "testing"

func Test_modelScoreAntiMonotone(t *testing.T) {
	// a <= b ==> score(a) >= score(b)

	tests := []struct {
		name string
		a, b ModelCounts
	}{
		{
			name: "Simple",
			a: ModelCounts{
				CriticalCount:              2,
				CriticalSensitiveFileCount: 0,
				MediumCount:                1,
				MediumSensitiveFileCount:   1,
				InformationalCount:         1,
				InfoSensitiveFileCount:     1,
			},
			b: ModelCounts{
				CriticalCount:              2,
				CriticalSensitiveFileCount: 1,
				MediumCount:                1,
				MediumSensitiveFileCount:   1,
				InformationalCount:         1,
				InfoSensitiveFileCount:     1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aScore := tt.a.scoreMetrics()
			bScore := tt.b.scoreMetrics()
			// t.Errorf("%s, %f, %f", tt.name, aScore, bScore)
			if aScore < bScore {
				t.Errorf("Score (a = %f) > (b = %f)\n %#v \n %#v", aScore, bScore, tt.a, tt.b)
			}
		})
	}

}
