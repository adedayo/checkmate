package gitlab

const (
	projectsQuery = `{
		    projects(first: %d, after: "%s") {
		      nodes {
		        name
		        id
		        archived
		        httpUrlToRepo
		        repository {
		          branchNames(offset: 0, searchPattern: "*", limit: 1000)
		        }
		        group {
		          id
		          name
		        }
		      }
		      pageInfo {
		        endCursor
		        hasNextPage
		      }
		    }
		  }
	`

	singleProjectQuery = `{
		projects(search: "%s") {
		  nodes {
			name
			id
			archived
			httpUrlToRepo
			group {
			  id
			  name
			}
		  }
		  pageInfo {
			endCursor
			hasNextPage
		  }
		}
	  }
`

//	projectsQuery = `{
//		projects(first: %d, after: "%s") {
//		  nodes {
//			name
//			description
//			id
//			archived
//			httpUrlToRepo
//			repository {
//			  branchNames(offset: 0, searchPattern: "*", limit: 1000)
//			}
//			group {
//			  id
//			  name
//			  description
//			}
//		  }
//		  pageInfo {
//			endCursor
//			hasNextPage
//		  }
//		}
//	  }
//
// `
)

type projectsQueryResult struct {
	Nodes    []GitLabProject
	PageInfo struct {
		EndCursor   string
		HasNextPage bool
	}
}

type GitLabProject struct {
	Name          string
	Description   string
	ID            string
	Archived      bool
	HttpUrlToRepo string
	Repository    struct {
		BranchNames []string
	}
	Group struct {
		ID          string
		Name        string
		Description string
	}
}
type GitLabProjectSearchResult struct {
	InstanceID             string
	Projects               []GitLabProject
	EndCursor              string
	HasNextPage            bool
	RemainingProjectsCount int64 //how many projects remain after this qeury cursor
}

// type GitLabProjects struct {
// 	Nodes    []GitLabProject
// 	PageInfo struct {
// 		EndCursor   graphql.String
// 		HasNextPage graphql.Boolean
// 	}
// }

// type projectQuery struct {
// 	Projects GitLabProjects `graphql:"projects(first: 7, after: $endCursor)"`
// }

// type GitLabProject struct {
// 	Name graphql.String
// 	// NameWithNamespace graphql.String
// 	Description graphql.String
// 	ID          graphql.ID
// 	Archived    graphql.Boolean
// 	// SshUrlToRepo      graphql.String
// 	HttpUrlToRepo graphql.String
// 	// WebUrl        graphql.String
// 	// Statistics    struct {
// 	// 	RepositorySize graphql.Float
// 	// 	StorageSize    graphql.Float
// 	// }
// 	Repository struct {
// 		// RootRef     graphql.String
// 		BranchNames []graphql.String `graphql:"branchNames(offset:0, searchPattern: \"*\", limit:1000)"`
// 	}
// 	// ProjectMembers struct {
// 	// 	Nodes []struct {
// 	// 		ID   graphql.String
// 	// 		User struct {
// 	// 			ID     graphql.String
// 	// 			Groups struct {
// 	// 				Nodes []struct {
// 	// 					ID   graphql.String
// 	// 					Name graphql.String
// 	// 				}
// 	// 			}
// 	// 		}
// 	// 	}
// 	// }
// 	Group struct {
// 		ID          graphql.ID
// 		Name        graphql.String
// 		Description graphql.String
// 		// FullName    graphql.String
// 		// EmailsDisabled graphql.Boolean
// 		// Contacts       struct {
// 		// 	Nodes []struct {
// 		// 		Email     graphql.String
// 		// 		FirstName graphql.String
// 		// 		LastName  graphql.String
// 		// 	}
// 		// }
// 		// GroupMembers struct {
// 		// 	Nodes []struct {
// 		// 		User struct {
// 		// 			ID               graphql.String
// 		// 			Username         graphql.String
// 		// 			GroupMemberships struct {
// 		// 				Nodes []struct {
// 		// 					ID    graphql.String
// 		// 					Group struct {
// 		// 						ID   graphql.String
// 		// 						Name graphql.String
// 		// 					}
// 		// 				}
// 		// 			}
// 		// 		}
// 		// 	}
// 		// }
// 		// Projects struct {
// 		// 	Nodes []struct {
// 		// 		ID            graphql.String
// 		// 		Name          graphql.String
// 		// 		HttpUrlToRepo graphql.String
// 		// 	}
// 		// }
// 	}
// }
