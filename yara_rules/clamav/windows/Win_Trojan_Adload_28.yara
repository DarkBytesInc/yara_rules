rule Win_Trojan_Adload_28
{
strings:
	$a0 = { 65205369676e696e6720434102033ffd9030 }
	$a1 = { 2e646f6c6c6172726576656e75652e636f6d2f65756c612e6173703f69643d }

condition:
	$a0 and $a1
}

        
