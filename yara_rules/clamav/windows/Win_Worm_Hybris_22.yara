rule Win_Worm_Hybris_22
{
strings:
	$a0 = { 10400081??????????81??04000000??75f1 }
	$a1 = { 104000c3 }

condition:
	$a0 and $a1
}

        
