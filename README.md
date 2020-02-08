[![Go Report Card](https://goreportcard.com/badge/github.com/adedayo/checkmate)](https://goreportcard.com/report/github.com/adedayo/checkmate)
![GitHub release](https://img.shields.io/github/release/adedayo/checkmate.svg)
[![GitHub license](https://img.shields.io/github/license/adedayo/checkmate.svg)](https://github.com/adedayo/checkmate/blob/master/LICENSE)

# CheckMate Code Security Analysis
CheckMate is designed to be a pluggable code security analysis tool with features to be added over time. Currently it supports

1. Detecting hard-coded secrets in code and configuration files

## Installation
Prebuilt binaries may be found for your operating system here: https://github.com/adedayo/checkmate/releases

For macOS X, you could install via brew as follows:
```bash
brew tap adedayo/tap
brew install checkmate
``` 


## Finding Hard-coded Secrets
Secrets such as passwords, encryption keys and other security tokens should never be embedded in the clear in code or configuration files. The secrets-finding feature of _CheckMate_ packs in a bunch of clever heuristics for determining whether a piece of string in a file is a secret. The heuristics include entropy of the string, the structural context such as variable names and properties the string is assigned to in different file types such as YAML, XML and other configuration file formats as well as source code such as Java, C/C++, C#, Ruby, Scala etc.

_CheckMate_ could be used/embedded in the following ways at the moment:

* As a *standalone API service* that could receive the textual content of a piece of data to check for secrets returning a JSON response containing all results that look suspiciously like secrets, along with justification of why it may be a secret and a confidence level of that determination
* As a *command-line tool* providing file paths and directories to scan for secrets. This is great for searching local file system for secrets
* As a Language Server Protocol (LSP) backend, using the LSP protocol to drive the analysis in LSP compatible text editors such as Visual Studio Code or Atom.


### Running _CheckMate_ as an API Service

To run _CheckMate_ as an API service, say on port 8080, simply run as follows

```bash 
checkmate api --port=8080
```

This may be tested as follows
```bash
curl -X POST -H "Content-Type: application/json" localhost:8080/api/findsecrets -d @<(cat <<EOF
{
 "source": "String pwd = \"N!,.aQBd/538:uy7Tx#(jUe?t6ret!\";\n
\n
String passphrase = \"This is a secret passphrase. No one will find out\";",
"source_type": ".java"
}
EOF
)
```

This returns a result (formatted for presentation) as follows:

```json
[
    {
        "Justification": {
            "Headline": {
                "Description": "Hard-coded secret assignment",
                "Confidence": "High"
            },
            "Reasons": [
                {
                    "Description": "Variable name suggests it is a secret",
                    "Confidence": "High"
                },
                {
                    "Description": "Value has a high entropy, may be a secret",
                    "Confidence": "Medium"
                }
            ]
        },
        "Range": {
            "Start": {
                "Line": 0,
                "Character": 7
            },
            "End": {
                "Line": 0,
                "Character": 45
            }
        },
        "Source": "pwd = \"N!,.aQBd/538:uy7Tx#(jUe?t6ret!\"",
        "ProviderID": "SecretAssignment"
    },
    {
        "Justification": {
            "Headline": {
                "Description": "Hard-coded secret assignment",
                "Confidence": "High"
            },
            "Reasons": [
                {
                    "Description": "Variable name suggests it is a secret",
                    "Confidence": "High"
                },
                {
                    "Description": "Hard-coded secret",
                    "Confidence": "High"
                }
            ]
        },
        "Range": {
            "Start": {
                "Line": 1,
                "Character": 8
            },
            "End": {
                "Line": 1,
                "Character": 72
            }
        },
        "Source": "passphrase = \"This is a secret passphrase. No one will find out\"",
        "ProviderID": "SecretAssignment"
    }
]
```

The _/api/findsecrets_ endpoint accepts a POST request with a JSON payload of the form 
```jsonc
{
    "source" : "<string data to scan>",
    "source_type": ".yaml", //a hint to help with parsing the text in source
    "base64" : true //an optional flag to indicate whether source is base64-encoded 
}
```

### Running _CheckMate_ as a command-line tool
```bash
checkmate secretSearch <paths to directories and files to scan>
```