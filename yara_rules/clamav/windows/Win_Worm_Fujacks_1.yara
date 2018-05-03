rule Win_Worm_Fujacks_1
{
strings:
	$a0 = { 436f6f6c5f47616d6553657475702e657865 }
	$a1 = { 545850316174666f726d2e657865 }
	$a2 = { 69686176656e6f70617373 }

condition:
	$a0 and $a1 and $a2
}

        
