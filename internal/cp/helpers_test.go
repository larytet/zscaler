package cp

import (
	"os"

	"github.com/larytet/zscaler/internal/broker"
)

type brokerSeg struct{ ID, Class string }

func toSegs(in []brokerSeg) []broker.Segment {
	var out []broker.Segment
	for _, s := range in {
		out = append(out, broker.Segment{ID: s.ID, Class: s.Class})
	}
	return out
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }
