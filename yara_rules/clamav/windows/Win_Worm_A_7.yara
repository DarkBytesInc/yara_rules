rule Win_Worm_A_7
{
strings:
	$a0 = { f5d50377ea91937a2e39aaab933338e339c3a34d826898cb95176fe5f0882d373d912a23fae5baee7de0b33e33aceb98d37ad42b55aa998fed751775cd35aa21 }

condition:
	$a0
}

        
