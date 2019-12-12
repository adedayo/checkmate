package secrets

import (
	"reflect"
	"testing"

	"github.com/adedayo/checkmate/pkg/common/diagnostics"
)

func Test_detectSecret(t *testing.T) {
	tests := []struct {
		name         string
		secret       string
		wantEvidence diagnostics.Evidence
	}{
		{
			name:   "SpecialCharacter",
			secret: "Ca`snn1djsrrddsd*",
			wantEvidence: diagnostics.Evidence{
				Description: descSuspiciousSecret,
				Confidence:  diagnostics.Medium},
		},
		{
			name:   "Suspicious",
			secret: "Casnn1djsrrddsd",
			wantEvidence: diagnostics.Evidence{
				Description: descSuspiciousSecret,
				Confidence:  diagnostics.Low},
		},
		{
			name:   "Empty string",
			secret: "",
			wantEvidence: diagnostics.Evidence{
				Description: descNotSecret,
				Confidence:  diagnostics.High},
		},
		{
			name:   "URLs",
			secret: "https://google.com",
			wantEvidence: diagnostics.Evidence{
				Description: descNotSecret,
				Confidence:  diagnostics.High},
		},
		{
			name:   "URNs",
			secret: "urn://google.com",
			wantEvidence: diagnostics.Evidence{
				Description: descNotSecret,
				Confidence:  diagnostics.High},
		},
		{
			name:   "Unusual secret characters - SPACES",
			secret: "Spaces and tabs are not expected",
			wantEvidence: diagnostics.Evidence{
				Description: descNotSecret,
				Confidence:  diagnostics.High},
		},
		{
			name:   "Unusual secret characters - TABS",
			secret: "Spaces\tand\ttabs\tare\tnot\texpected",
			wantEvidence: diagnostics.Evidence{
				Description: descNotSecret,
				Confidence:  diagnostics.High},
		},
		{
			name:   "Unusual starting character",
			secret: "<this13d99cun9ue9unx9uxn91un9uw1nx9un9uwn9xu1nwx9u1nw9x></this13d99cun9ue9unx9uxn91un9uw1nx9un9uwn9xu1nwx9u1nw9x>",
			wantEvidence: diagnostics.Evidence{
				Description: descNotSecret,
				Confidence:  diagnostics.High},
		},
		{
			name:   "Encoded Secret",
			secret: "CAFEBABE1234DEADBEEF122nCAB810033e13e",
			wantEvidence: diagnostics.Evidence{
				Description: descEncodedSecret,
				Confidence:  diagnostics.High},
		},
		{
			name:   "Common Secret",
			secret: "password1",
			wantEvidence: diagnostics.Evidence{
				Description: descCommonSecret,
				Confidence:  diagnostics.High},
		},
		{
			name:   "Not Secret",
			secret: "secret",
			wantEvidence: diagnostics.Evidence{
				Description: descNotSecret,
				Confidence:  diagnostics.Low},
		},
		{
			name:   "High Entropy",
			secret: "HbjZ!+{c]Y5!kNzB+-p^A6bCt(zNtf=V",
			wantEvidence: diagnostics.Evidence{
				Description: descHighEntropy,
				Confidence:  diagnostics.Medium},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotEvidence := detectSecret(tt.secret); !reflect.DeepEqual(gotEvidence, tt.wantEvidence) {
				t.Errorf("detectSecret() = %v, want %v", gotEvidence, tt.wantEvidence)
			}
		})
	}
}

func Test_getShannonEntropy(t *testing.T) {
	tests := []struct {
		name string
		data string
		want float64
	}{
		{
			name: "Test Empty",
			data: "",
			want: 0,
		},
		{
			name: "Test Single Character",
			data: "a",
			want: 0,
		},
		{
			name: "Some data",
			data: "1223334444",
			want: 1.8464393446710154,
		},
		{
			name: "High Entropy",
			data: "HbjZ!+{c]Y5!kNzB+-p^A6bCt(zNtf=V",
			want: 4.625,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getShannonEntropy(tt.data); got != tt.want {
				t.Errorf("getShannonEntropy() = %v, want %v", got, tt.want)
			}
		})
	}
}
