rule Win_Trojan_Crypted_33
{
strings:
	$a0 = { 68001040005868??????005f33dbeb0d8a140380ea0780f2048814034381fb??????0072ebffe7052b0e03021a05003068060a2b060104018237020104a05a3058 }

condition:
	$a0
}

        