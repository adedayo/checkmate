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


Your code security rating is {{ .Grade }}


image::{{ .Chart }}[top=25%, align=center, pdfwidth=4.0in]



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
| Issues per file type | {{ .IssuesPerType }}
| Average number of issues per file | {{ .AveragePerFile }}
|===

<<<

== Issue Details


{{ range $index, $issue := .Issues }}
{{ template "ISSUE" $issue }}


{{ end }}


{{ define "ISSUE" }}


*Problem {counter:seq}*. {{ .Justification.Headline.Description }}, *Confidence*: {{ .Justification.Headline.Confidence }} 


*Source code evidence*:

*File*: {{ .Location }}
[source,{{ computeLanguage .Location }}]
----
{{ .Source }}
----
*Found at*: Line {{ .Range.Start.Line }}, Char {{ .Range.Start.Character }} *=>* Line {{ .Range.End.Line }}, Char {{ .Range.End.Character }}. *Found by*: {{ .ProviderID }}.


*Analysis*
{{ range $index, $evidence := .Justification.Reasons }}
{{ translateConfidence $evidence.Confidence }} {{ $evidence.Description }} *Confidence* {{ $evidence.Confidence }}
{{ end }}

---
{{ end }}


`
