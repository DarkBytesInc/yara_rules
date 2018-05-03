rule Win_Worm_Darker_2
{
strings:
	$a0 = { da7657202085f93868bbe4f189b6bac3d5ecf745a4da2a29d868738f381ec572ef7eb8472c2254297b2b3754d7544a41ec8870bf1cefc7c2fecada0dd56c029d079b462e908696e3f3fb894f7093a091 }

condition:
	$a0
}

        
