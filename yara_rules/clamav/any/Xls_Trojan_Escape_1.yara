rule Xls_Trojan_Escape_1
{
strings:
	$a0 = { 74696d6576616c7565[0-14]22737461727475702e786c732179636f7022 }
	$a1 = { 6f6e2e73746172747570 }

condition:
	$a0 and $a1
}

        
