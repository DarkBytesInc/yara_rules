rule Win_Trojan_Unicode_174_138_171_62_1
{
strings:
	$a0 = { 3100370034002e003100330038002e003100370031002e00360032 }

condition:
	$a0
}

        
