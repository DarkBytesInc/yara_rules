rule Win_Worm_Rays_3
{
strings:
	$a0 = { 515383c404565e83ec0483c40481efcb47d14d81c7cb47d14d897c24fc83ec0451 }

condition:
	$a0
}

        
