package assets

//Report is the diagnostic report template
var Report = `:title-page:
:title-logo-image: image:{{ .Logo }}[top=25%, align=center, pdfwidth=4.0in]
:icons: font
:author: https://github.com/adedayo/checkmate
:email: dayo@securityauditlabs.com
:revdate: {{ .TimeStamp }}
:description: A static security audit of your codebase
:sectnums:
:listing-caption:

= CheckMate Report: image:{{ .SALLogo }}[align=center, pdfwidth=0.2in] Code security audit 
:source-highlighter: rouge

== Executive Summary
This is a report of the security audit of your codebase completed at {{ .TimeStamp }}

[cols="2a,5a",frame=none,grid=none]
|===

^|[cols="1",frame=none,grid=none]
!===
^!Overall Security Grade
a!image::{{ .GradeLogo }}[align=center, pdfwidth=40%]
!===

^|[cols="1",frame=none,grid=none]
!===
^!Issues Found
a!image::{{ .Chart }}[align=center, pdfwidth=100%]
!===

|===


=== Metrics about your codebase
The following is a summary of metrics calculated during the security audit of your codebase:


[cols="h,d"]
|===
| Total number of issues | {{ len .Issues }}
| Total number of High Issues| {{ .HighCount }}
| Total number of Medium Issues| {{ .MediumCount }}
| Total number of Low Issues| {{ .LowCount }}
| Total number of Informational Issues| {{ .InformationalCount }}
| No of files processed | {{ .FileCount }}
| No of Reused Secrets | {{ .ReusedSecretsCount }}
| No Instances of Secret Reuse | {{ .NumberOfSecretsReuse }}
| Average number of issues per file | {{ .AveragePerFile }}
|===

<<<

== Issue Details


{{ template "ISSUE" . }}



{{ define "ISSUE" }}

{{ $showSource := .ShowSource }}
{{ $reusedSecrets := .ReusedSecrets }}
{{ range $index, $issue := .Issues }}


*Problem {counter:seq}*. {{ $issue.Justification.Headline.Description }}, *Confidence*: {{ $issue.Justification.Headline.Confidence }} 

*Source code evidence*:

*File*: {{ $issue.Location }}
{{ if $showSource }}
{{ if $issue.Source }}
[source,{{ computeLanguage $issue.Location }}]
----
{{ $issue.Source }}
----
{{ end }}
{{ end }}
*Found at*: Line {{ increment $issue.Range.Start.Line }}, Char {{ increment $issue.Range.Start.Character }} *=>* Line {{ increment $issue.Range.End.Line }}, Char {{ increment $issue.Range.End.Character }}. *Found by*: {{ $issue.ProviderID }}.
{{- if $issue.SHA256 -}}
{{- $sha := deref $issue.SHA256 }}

*SHA256*: {{ $sha }}

*No of times secret (re)used*: {{ len (index $reusedSecrets $sha) }}
{{ end }}

*Analysis*
{{ range $index, $evidence := $issue.Justification.Reasons }}
{{ translateConfidence $evidence.Confidence }} {{ $evidence.Description }} *Confidence* {{ $evidence.Confidence }}
{{ end }}

---
{{ end }}
{{ end }}
`
