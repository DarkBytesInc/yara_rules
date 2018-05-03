rule Win_Worm_Tami_2
{
strings:
	$a0 = { 5c737472616e676c65722e657865 }
	$a1 = { 6f70656e[0-4]5c54616d69616d692e766273[0-4]5c54616d69616d692e777264 }

condition:
	$a0 and $a1
}

        
