rule Win_Worm_Mytob_409
{
strings:
	$a0 = { 558bec53565760e8000000005d81ed6c284000b95d34400081e9c62840008bd581c2c62840008d3a8bf733c0eb0490eb01c2ac }

condition:
	$a0
}

        
