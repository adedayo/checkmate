module github.com/adedayo/checkmate

go 1.14

require (
	github.com/adedayo/checkmate-core v0.0.3
	github.com/adedayo/checkmate-plugin v0.0.3
	github.com/adedayo/go-lsp v0.0.6
	github.com/blend/go-sdk v2.0.0+incompatible // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/gorilla/mux v1.7.4
	github.com/mitchellh/go-homedir v1.1.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.0
	github.com/wcharczuk/go-chart v2.0.1+incompatible
	golang.org/x/image v0.0.0-20200430140353-33d19683fad8 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200506231410-2ff61e1afc86
)

//replace github.com/adedayo/go-lsp v0.0.6 => ../go-lsp
// replace github.com/adedayo/checkmate-core v0.0.3 => ../checkmate-core
