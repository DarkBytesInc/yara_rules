rule Win_Trojan_Spambot_167
{
strings:
	$a0 = { e79ff6ffa358a19f85b6912d5e443ad4d3678ef3b9c527b189b7ffffffff2ce181c08a05d889546b5fbbb5d1512a6de6dd7f5c623d3677dbbf2a6115b5e5fffffffffa8118d33078e8507863e49cf7e2980373a04a2b665d1960df20ed08caa764b8ffffffff972280d64cc50739 }

condition:
	$a0
}

        
