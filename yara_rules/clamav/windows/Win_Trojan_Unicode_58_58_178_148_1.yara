rule Win_Trojan_Unicode_58_58_178_148_1
{
strings:
	$a0 = { 350038002e00350038002e003100370038002e003100340038 }

condition:
	$a0
}

        
