rule Win_Spyware_515_2
{
strings:
	$a0 = { ff35a868410068??4b4100ff3594684100 }
	$a1 = { 0e000000656e643b6d656e616d65646c6c3a0000ffffffff0b000000656e643b7378706f7274 }

condition:
	$a0 and $a1
}

        
