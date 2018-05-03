rule Email_Trojan_Trojan_743
{
strings:
	$a0 = { 596f75204e6f77202620466f7265766572200d0a0d0a73656520617474616368 }

condition:
	$a0
}

        
