rule Win_Trojan_Vgen_139
{
strings:
	$a0 = { 8ec00e1f26a14000268b1e4200a36b07891e6d0726a18400268b1e8600a36f07891e7107fa26c70684008d07268c }

condition:
	$a0
}

        
