rule Win_Worm_Autorun_303
{
strings:
	$a0 = { 558bec83c4f0b8d0590200e8d4e1ffff33c05568bf5a020064ff306489206a006a00e8b9e2ffffe87ce2ffff6a }

condition:
	$a0
}

        
