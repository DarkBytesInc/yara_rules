rule Win_Trojan_Bancos_1019
{
strings:
	$a0 = { 00a5fcd1335faf9cefcabc1dcf7efa3b49d61f75aeb79dc6bb3ffbdb038ea89ab756d9d8c1ffb310461734286ab79aba712bd250a50809c731e7646f6969cd129f66d620c9fdcd8e3a16d0b7d85c064c23f6cf944d75eb3f }

condition:
	$a0
}

        
