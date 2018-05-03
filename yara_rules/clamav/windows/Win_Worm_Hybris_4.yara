rule Win_Worm_Hybris_4
{
strings:
	$a0 = { 84150000be00104000bd0313e052292e81ed40219d0383eefc4b75f2e9cea9ffff00000000 }

condition:
	$a0
}

        
