rule Win_Worm_Hybris_15
{
strings:
	$a0 = { 4000bd003b5b02012b81f5407a5c0183c30490e2f2e9beb4ffff00000000 }

condition:
	$a0
}

        
