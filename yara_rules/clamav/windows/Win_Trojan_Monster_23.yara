rule Win_Trojan_Monster_23
{
strings:
	$a0 = { 02be7e1180346d46e2faeb25364d2022233e39283f4d30316d4743476d47432e22206d57f2f684007d6d7977a243 }

condition:
	$a0
}

        
