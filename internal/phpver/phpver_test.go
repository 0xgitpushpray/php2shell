package phpver

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in                 string
		want               string
		prerelease, vendor bool
		wantErr            bool
	}{
		{in: "8.3.12", want: "8.3.12"},
		{in: "PHP/8.4.27", want: "8.4.27"},
		{in: " 8.5.0RC2 ", want: "8.5.0RC2", prerelease: true},
		{in: "8.6.0-dev", want: "8.6.0-dev", prerelease: true},
		{in: "8.5.0alpha1", want: "8.5.0alpha1", prerelease: true},
		{in: "8.1.2-1ubuntu2.14", want: "8.1.2-1ubuntu2.14", vendor: true},
		{in: "7.4.33+deb11u5", want: "7.4.33+deb11u5", vendor: true},
		{in: "8.3", wantErr: true},
		{in: "latest", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		v, err := Parse(tt.in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("Parse(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
		if tt.wantErr {
			continue
		}
		if v.String() != tt.want || v.Prerelease() != tt.prerelease || v.VendorBuild() != tt.vendor {
			t.Errorf("Parse(%q) = %q prerelease=%v vendor=%v; want %q %v %v",
				tt.in, v, v.Prerelease(), v.VendorBuild(), tt.want, tt.prerelease, tt.vendor)
		}
	}
}

func TestCompare(t *testing.T) {
	a, _ := Parse("8.3.9")
	b, _ := Parse("8.3.36")
	c, _ := Parse("8.3.36-1ubuntu1")
	if Compare(a, b) != -1 || Compare(b, a) != 1 || Compare(b, c) != 0 {
		t.Fatal("Compare must compare numerically and ignore suffixes")
	}
}
