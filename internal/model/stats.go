package model

import "iter"

const (
	StatsSourcesTotal  = "/sources/total"
	StatsErrSources    = "/sources/error"
	StatsFilesTotal    = "/files/total"
	StatsFilesExcluded = "/files/excluded"
	StatsFilesErr      = "/files/error"
)

type Stats interface {
	IncSources()
	IncErrSources()
	IncFiles()
	IncExcludedFiles()
	IncErrFiles()
	Stats() iter.Seq2[string, string]
}
