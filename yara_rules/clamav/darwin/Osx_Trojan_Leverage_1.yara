rule Osx_Trojan_Leverage_1
{
strings:
	$a0 = { e8ef671b008b65acb80fa115008945f0b9232b0000894de85050506800000000 }
	$a1 = { 505050ff75e0[0-50]ff75f8e8b4671b008b65ac33c0 }

condition:
	$a0 and $a1
}

        
