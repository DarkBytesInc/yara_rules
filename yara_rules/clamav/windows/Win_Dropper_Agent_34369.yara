rule Win_Dropper_Agent_34369
{
strings:
	$a0 = { 656374696f6e00fd958000455a566964656f5c434c534944007b }
	$a1 = { 4e756c6c736f667420496e7374616c6c2053797374 }

condition:
	$a0 and $a1
}

        
