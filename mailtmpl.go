package certexpire

var emailtmpl = `From: <{{ .From }}>
To: <{{ .Report.MailTo }}>
Subject: SSL certificates check failed

The following servers have failed the TLS certificate check:
{{ range $e := .Report.Checks }}
{{- if or $e.Error $e.ExecuteError }}
{{ $e.Hostname }}:{{ $e.Param}} ({{$e.Protocol}}): Expires {{ $e.ExpireTime }}
{{ if $e.Error -}} {{- range $err := $e.Error }} ==> {{ $err}} {{- end}} {{- end}} 
{{ if $e.ExecuteError -}} ==> ({{$e.ExecuteError}}) {{- end -}} 
{{- end -}}
{{- end }}

Update ASAP!
`
