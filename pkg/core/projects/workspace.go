package projects

import (
	"log"
	"time"
)

var (
	nothing = struct{}{}
)

func SimpleWorkspaceSummariser(pm ProjectManager, workspacesToUpdate []string) (*Workspace, error) {
	wspaces, err := pm.GetWorkspaces()
	if err != nil {
		log.Printf("SimpleWorkspaceSummariser: %v", err)
		return nil, err
	}
	if len(workspacesToUpdate) > 0 {
		toUpdate := make(map[string]struct{})
		for _, w := range workspacesToUpdate {
			toUpdate[w] = nothing
		}

		ws := make(map[string][]*ProjectSummary)
		for _, s := range pm.ListProjectSummaries() {
			w := s.Workspace
			if _, present := toUpdate[w]; !present {
				//ignore project summary if not in workspace(s) of interest
				continue
			}
			///add project summary to the list to process
			if wsw, present := ws[w]; present {
				ws[w] = append(wsw, s)
			} else {
				ws[w] = []*ProjectSummary{s}
			}
		}

		workspaceSummary := Workspace{
			Details: make(map[string]*WorkspaceDetail),
		}

		tStamp := time.Now().UTC().Format(time.RFC1123)
		for w, pss := range ws {
			psModels := make([]*Model, len(pss))
			for _, ps := range pss {
				psModels = append(psModels, ps.LastScanSummary.AdditionalInfo)
			}
			workspaceSummary.Details[w] = &WorkspaceDetail{
				Summary:          MergeModels(tStamp, psModels...).Summarise(),
				ProjectSummaries: ws[w],
			}
			psModels = nil
		}
		ws = nil

		if wspaces.Details == nil {
			wspaces.Details = make(map[string]*WorkspaceDetail)
		}

		//update the newly-calculated workspace summary details
		for w, wd := range workspaceSummary.Details {
			wspaces.Details[w] = wd
		}
		workspaceSummary.Details = nil
	}
	return wspaces, nil
}
