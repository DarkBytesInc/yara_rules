rule Win_Worm_Yahos_2
{
strings:
	$a0 = { 6a6068a80c4100e82a110000bf940000008bc7e87a1200008965e88bf4893e56 }

condition:
	$a0
}

        
