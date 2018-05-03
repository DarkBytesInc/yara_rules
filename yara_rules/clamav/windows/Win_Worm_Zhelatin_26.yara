rule Win_Worm_Zhelatin_26
{
strings:
	$a0 = { bb953640008d4d1c8d78088d450881eee12e00004fbf6e }
	$a1 = { b97e4d485033c82d2f4c0050 }

condition:
	$a0 and $a1
}

        
