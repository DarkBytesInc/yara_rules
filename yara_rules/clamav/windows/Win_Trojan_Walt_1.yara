rule Win_Trojan_Walt_1
{
strings:
	$a0 = { e800005d81ed08018db6950101010157a5a4c6866902011acd8d963e022172b824357411899e3a028c863c02b425 }

condition:
	$a0
}

        
