rule Win_Trojan_Virut_391
{
strings:
	$a0 = { 33c9b104014c24??68????????c3 }

condition:
	$a0
}

        
