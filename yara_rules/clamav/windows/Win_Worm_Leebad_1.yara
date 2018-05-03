rule Win_Worm_Leebad_1
{
strings:
	$a0 = { c745fc00000000b911000000be1cb342008dbd00fffffff3a566a5b907000000bed4a142008dbde4fefffff3a58b45085068b0a142008d8d48ffffff51e8b1010000 }

condition:
	$a0
}

        
