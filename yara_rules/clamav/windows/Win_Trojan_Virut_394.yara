rule Win_Trojan_Virut_394
{
strings:
	$a0 = { 33d2b204015424??68????????c3 }

condition:
	$a0
}

        
