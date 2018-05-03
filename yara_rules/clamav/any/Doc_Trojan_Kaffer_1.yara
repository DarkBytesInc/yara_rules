rule Doc_Trojan_Kaffer_1
{
strings:
	$a0 = { 313929202d203129 }
	$a1 = { 2e416e696d6174696f6e203d2028726e646d283629202d203129 }
	$a2 = { 2e54657874203d2043727970742822cca5cde4f1e0a5cee4e3e3e0f7f6a5a8a5d1ede0fca5e9ec }

condition:
	$a0 and $a1 and $a2
}

        
