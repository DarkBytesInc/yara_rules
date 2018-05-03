rule Win_Worm_Hybris_12
{
strings:
	$a0 = { fc684c404000ff1500404000a30a2340 }

condition:
	$a0
}

        
