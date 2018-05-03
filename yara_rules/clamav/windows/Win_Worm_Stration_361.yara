rule Win_Worm_Stration_361
{
strings:
	$a0 = { 4ae3512a4547bcbe54443e1cbb3898edc22207dc6f70f4aa0807d62951be279f7d229a864da2d1be66bb6465675577da7cfa385fc794e68cdf2cc1dbdd283e7b412f900c6366ec611483a2cd5f16e4ae }

condition:
	$a0
}

        
