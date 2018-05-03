rule Win_Trojan_Java_98
{
strings:
	$a0 = { 47657457696e646f77734469726563746f7279 }
	$a1 = { 2e657865 }
	$a2 = { 55524c446f776e6c6f6164546f46696c65 }
	$a3 = { 52756e74696d65 }
	$a4 = { 65786563 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
