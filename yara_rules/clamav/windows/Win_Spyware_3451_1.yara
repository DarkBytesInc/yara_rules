rule Win_Spyware_3451_1
{
strings:
	$a0 = { 51562bf15e0f00c1eb008b0c2483c40415a8240000e84c02000005235960107100 }

condition:
	$a0
}

        
