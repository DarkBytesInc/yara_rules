rule Win_Worm_Autorun_434
{
strings:
	$a0 = { 4100550054004f00520055004e }
	$a1 = { 5300680065006c006c0065007800650063007500740065 }

condition:
	$a0 and $a1
}

        
