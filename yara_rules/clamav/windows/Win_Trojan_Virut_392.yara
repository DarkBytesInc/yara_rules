rule Win_Trojan_Virut_392
{
strings:
	$a0 = { 33c0b004014424??68????????c3 }

condition:
	$a0
}

        
