rule Win_Trojan_IRC_Script_16
{
strings:
	$a0 = { 696620282431203d20666c6f6f642e6329207b20536861646f77536f636b20536861646f772a206a6f696e202432207c20536861646f77536f636b20536861646f772a20707269766d7367202432203a2024332d207c20536861646f77536f636b20536861646f772a206e6f74696365202432 }

condition:
	$a0
}

        