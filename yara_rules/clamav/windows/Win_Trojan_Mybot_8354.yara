rule Win_Trojan_Mybot_8354
{
strings:
	$a0 = { 0c40cf0e4cbc50e018ab5ba4bd9dd6d5294a83a2b2c3f21f7816662032d33b390fe07ddbef0b4baaa5b18638858c06448bec743b2c208a9a891eedc30bf8e48d5a2bd26ad891a5e47fb2e7761820321ed414f3ff26 }

condition:
	$a0
}

        
