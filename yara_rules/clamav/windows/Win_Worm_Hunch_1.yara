rule Win_Worm_Hunch_1
{
strings:
	$a0 = { c745fc0e000000c7458894264000c74580080000006a1058e88c39ffff }

condition:
	$a0
}

        
