rule Win_Worm_mrc_1
{
strings:
	$a0 = { 6e343d6f6e20313a4a6f696e3a233a696620246368616e203d20237669727573202f7061727420246368616e }

condition:
	$a0
}

        