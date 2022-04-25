package scheduler

import (
	"context"
	"fmt"

	"github.com/adedayo/checkmate-core/pkg/projects"
	"github.com/adedayo/checkmate/pkg/api"
	"github.com/mitchellh/go-homedir"
	"github.com/robfig/cron/v3"
)

func schedule(spec string, f func()) {
	c := cron.New()
	c.AddFunc(spec, f)
	c.Start()
}

func ScheduleReposiroryTracking(config Config) {
	dataDir, _ := homedir.Expand(config.DataDir)
	pm := projects.MakeSimpleProjectManager(dataDir)
	spec := fmt.Sprintf("@every %ds", config.Frequency)

	schedule(spec, func() {
		updateCommitDBs(context.Background(), pm, callback, config)
	})

	select {}

}

func callback(projID string, data interface{}) {
	for _, ws := range api.GetListeningSocketsByProjectID(projID) {
		ws.WriteJSON(data)
	}
}

type Config struct {
	Frequency        int    //how often, in seconds the schedule should be run
	DataDir          string //CheckMate data directory
	ScanOlderCommits bool   //whether commits, prior to HEAD, should be scanned. TODO: set this from the parameters
}
