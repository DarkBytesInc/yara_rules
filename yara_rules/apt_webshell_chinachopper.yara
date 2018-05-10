
rule ChinaChopper_Generic {
	  meta:
    description = "China Chopper Webshells - PHP and ASPX"
    author = "Florian Roth"
    reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"
    date = "2015/03/10"
    severity = "10"
    type = "Advanced Persistent Threat"
	strings:
		$aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(RequestItem\[.{,100}unsafe/
		$php = /<?php.\@eval\(\$_POST./
	condition:
		1 of them
}
