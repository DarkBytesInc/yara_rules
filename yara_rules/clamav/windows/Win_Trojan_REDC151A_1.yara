rule Win_Trojan_REDC151A_1
{
strings:
	$a0 = { 40b90500ba3105e81e04582de90526894515b44033c9e80f045826884504b801575a59e80204b4 }

condition:
	$a0
}

        
