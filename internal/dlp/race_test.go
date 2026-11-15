//go:build race

package dlp

const raceSlowdown = 15 // the race detector slows code down by roughly 5 to 15 times
