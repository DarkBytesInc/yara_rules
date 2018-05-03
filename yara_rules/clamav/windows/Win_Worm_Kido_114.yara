rule Win_Worm_Kido_114
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f6 }
	$a1 = { fecb718d9463787571 }

condition:
	$a0 and $a1
}

        
