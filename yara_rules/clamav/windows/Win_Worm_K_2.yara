rule Win_Worm_K_2
{
strings:
	$a0 = { 24fe352c6bbaf66853f1856f8afe3acea312c5fda67c02f241ccc089f1ce602bcfa0718fe0d19dd15dbcea5d23d490bb6ea1b1754e75ecd49293835386f567efcf3a8555b59c8dad665c03ee26929c37ed5358fb433a1ca23765318eb3a735f6 }

condition:
	$a0
}

        
