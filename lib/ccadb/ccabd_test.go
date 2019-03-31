package ccadb

import "testing"

func TestGetHeader(t *testing.T) {
	report, err := NewReport()
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range report.Records {
		t.Log(record.TestWebsiteRevoked())
	}
}
