module github.com/adedayo/checkmate

go 1.20

require (
	github.com/adedayo/checkmate-badger-project-manager v0.9.0
	github.com/adedayo/checkmate-core v0.9.0
	github.com/adedayo/checkmate-plugin v0.9.0
	github.com/adedayo/git-service-driver v0.9.0

	// github.com/adedayo/code-intel-service v0.0.1
	github.com/adedayo/go-lsp v0.0.9
	github.com/go-git/go-git/v5 v5.6.1
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.5.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/robfig/cron/v3 v3.0.1
	github.com/spf13/cobra v1.7.0
	github.com/spf13/viper v1.15.0
	github.com/wcharczuk/go-chart/v2 v2.1.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/adedayo/ldap-sync v0.0.3

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20230426101702-58e86b294756 // indirect
	github.com/acomagu/bufpipe v1.0.4 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/dgraph-io/badger/v3 v3.2103.5 // indirect
	github.com/dgraph-io/ristretto v0.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.4 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.4.1 // indirect
	github.com/go-ldap/ldap/v3 v3.4.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/golang/glog v1.1.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/flatbuffers v23.3.3+incompatible // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.15 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.16.5 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.0.7 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sergi/go-diff v1.3.1 // indirect
	github.com/skeema/knownhosts v1.1.0 // indirect
	github.com/spf13/afero v1.9.5 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/crypto v0.8.0 // indirect
	golang.org/x/image v0.7.0 // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/tools v0.8.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
)

// replace github.com/adedayo/checkmate-core v0.9.0 => ../checkmate-core

// replace github.com/adedayo/ldap-sync v0.0.3 => ../../ldap/ldap-sync

// replace github.com/adedayo/git-service-driver v0.9.0 => ../git-service-driver
// replace github.com/adedayo/checkmate-plugin v0.9.0 => ../checkmate-plugin

// replace github.com/adedayo/checkmate-badger-project-manager v0.9.0 => ../checkmate-badger-project-manager

// replace github.com/adedayo/code-intel-service v0.0.1 => ../code-intel-service
// replace github.com/adedayo/go-lsp v0.0.9 => ../go-lsp
