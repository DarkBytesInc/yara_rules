rule Win_Trojan_DNSChanger_83
{
strings:
	$a0 = { 0d9122d54d7b853a167a9b301fbb86c7d3d94f88630672165f06d3cc404dc18e648a0a6a0e7b86fd62879548aa7b86c498bcc2478a83fad49abf8edc1c0710c50d7bbf14728a0a460e7b864f7edb110a1a3c6ed5106cec49cef08fd3c4c092ef538b711899c19e1799d9aa1b99f9a6c7e67e7f00d004cbbc97d082433b068dc7ceef9d44467bfad60cf1 }

condition:
	$a0
}

        