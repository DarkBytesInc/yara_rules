rule Win_Worm_Ecopic_1
{
strings:
	$a0 = { c745fc18000000c785e4feffffc4324000c785dcfeffff080000006a1058e82db5ffff8db5dcfeffff8bfca5a5a5a568043340008d459050e875b6ffff50e83fb6ffff }

condition:
	$a0
}

        
