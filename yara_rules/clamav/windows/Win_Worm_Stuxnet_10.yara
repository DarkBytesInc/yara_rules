rule Win_Worm_Stuxnet_10
{
strings:
	$a0 = { 6a1868283e0100e84a1e000033db895dfcc7052041010080000000680002000053ff15b42301 }

condition:
	$a0
}

        
