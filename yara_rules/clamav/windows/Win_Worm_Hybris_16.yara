rule Win_Worm_Hybris_16
{
strings:
	$a0 = { 4252495300fc684c804000ff1500804000a39623400083c4808bcc50e880000000 }

condition:
	$a0
}

        
