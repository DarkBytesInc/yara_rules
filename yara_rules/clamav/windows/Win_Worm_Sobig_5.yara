rule Win_Worm_Sobig_5
{
strings:
	$a0 = { 3cdf78d10cf4ca79c503a8ca1c8fb0df57868abae75470ca27f24e3bc701bcc775ab8b2389147d5205593a629610da5a62 }

condition:
	$a0
}

        
