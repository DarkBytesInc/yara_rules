rule Win_Trojan_Unicode_112_175_184_57_1
{
strings:
	$a0 = { 3100310032002e003100370035002e003100380034002e00350037 }

condition:
	$a0
}

        
