package remote

import "testing"

func TestShellQuoting(t *testing.T) {
	got := Shell("docker", "run", "--label", "a=it's", "{{.Names}}")
	want := `'docker' 'run' '--label' 'a=it'\''s' '{{.Names}}'`
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}
