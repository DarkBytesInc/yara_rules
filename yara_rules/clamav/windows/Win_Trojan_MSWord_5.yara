rule Win_Trojan_MSWord_5
{
strings:
	$a0 = { 5120655566744cc01e2243003a5c6d5743684555442e220007226578c30022c1a1044f70656e }

condition:
	$a0
}

        
