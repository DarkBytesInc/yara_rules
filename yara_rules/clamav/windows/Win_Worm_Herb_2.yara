rule Win_Worm_Herb_2
{
strings:
	$a0 = { ba704b4000e865f0ffff6a008b45fce847f1ffff508d45fce886f3ffff50a12087400050e856fbffff6a006a008b45f0e81ef3ffff }

condition:
	$a0
}

        
