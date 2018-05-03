rule Win_Worm_Alcobul_1
{
strings:
	$a0 = { 6563686f20225058223d22633a5c5c58505c5c78702e62617422203e3e20633a5c582e726567 }

condition:
	$a0
}

        
