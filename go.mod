module github.com/adedayo/checkmate

go 1.13

require (
	github.com/adedayo/go-lsp v0.0.6
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/mitchellh/go-homedir v1.1.0
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
	github.com/wcharczuk/go-chart v2.0.2-0.20191206192251-962b9abdec2b+incompatible
	go.uber.org/zap v1.10.0
	golang.org/x/image v0.0.0-20200119044424-58c23975cae1 // indirect
	gopkg.in/src-d/go-git.v4 v4.13.1
	gopkg.in/yaml.v3 v3.0.0-20191120175047-4206685974f2
)

//replace github.com/adedayo/go-lsp v0.0.6 => ../go-lsp
