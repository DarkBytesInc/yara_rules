rule Win_Trojan_Velost_1
{
strings:
	$a0 = { ff5610ff564cb918000000ba433a5c00515254ff561483f802720b83f805740654e8060000005a4259e2e5c3 }

condition:
	$a0
}

        
