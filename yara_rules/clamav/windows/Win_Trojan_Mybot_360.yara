rule Win_Trojan_Mybot_360
{
strings:
	$a0 = { e01b5fda2d72e9e98bcb4a565986382ffc4ebc190de1055502127464c393172bc4d5fd54312100b19dc170c6362fb10b023069bab1d3af5a3cd785497d3fb002b64e70b131ce80a9aa30286662d36a4726455c651c04081aee16052ad9223801835ac112c408c695a49722251b34e13ae10ba1170c7cd01e19abc2efdb6d133a6acecc24bd7d8f382235e82cc484a4ae12ba93ed723e }

condition:
	$a0
}

        