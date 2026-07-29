package secrets

import (
	"reflect"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

func Test_detectSecret(t *testing.T) {
	tests := []struct {
		name         string
		secret       string
		wantEvidence diagnostics.Evidence
	}{
		{
			name:   "mongo",
			secret: `mongodb://mongouser:mongopwd@mongoserver.com:123456/path`,
			wantEvidence: diagnostics.Evidence{
				Description: "MongoDB Database " + descConnectionURI,
				Confidence:  diagnostics.High},
		},
		{
			name:   "numbers only should not be detected",
			secret: `56987654123456`,
			wantEvidence: diagnostics.Evidence{
				Description: descNotSecret,
				Confidence:  diagnostics.High},
		},
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
			name:   "GitHub Secret",
			secret: "gho_pTruZn7ntsbrTERIYU4sGx3Qq4689V2Jzoq1",
			wantEvidence: diagnostics.Evidence{
				Description: "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.",
				Confidence:  diagnostics.High},
		},
		{
			name:   "Slack Token",
			secret: "xoxb-" + "333649436676-799261852869-clFJVVIaoJahpORboa3Ba2al",
			wantEvidence: diagnostics.Evidence{
				Description: "Slack Bot/User Token",
				Confidence:  diagnostics.Critical},
		},
		{
			name:   "Stripe Token",
			secret: "sk_test_" + "26PHem9AhJZvU623DfE1x4sd",
			wantEvidence: diagnostics.Evidence{
				Description: "Stripe/PayStack Token",
				Confidence:  diagnostics.Critical},
		},
		{
			name:   "GoCardless Token",
			secret: "live_y7VPTOdgFZtFaAS9V8HT3",
			wantEvidence: diagnostics.Evidence{
				Description: descGoCardlessToken,
				Confidence:  diagnostics.Critical},
		},

		{
			name:   "Common Secret",
			secret: "password1",
			wantEvidence: diagnostics.Evidence{
				Description: descCommonSecret,
				Confidence:  diagnostics.Medium},
		},
		{
			name:   "Not Secret",
			secret: "secret",
			wantEvidence: diagnostics.Evidence{
				Description: descNotSecret,
				Confidence:  diagnostics.High},
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
			if gotEvidence := detectSecret(secretContext{secret: tt.secret}); !reflect.DeepEqual(gotEvidence, tt.wantEvidence) {
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
