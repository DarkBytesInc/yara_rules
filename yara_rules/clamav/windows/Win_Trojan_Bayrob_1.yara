rule Win_Trojan_Bayrob_1
{
strings:
	$a0 = { 558bec6aff68205c410064a100000000506489250000000083ec0c53565733f68965f0[5]8d4de88975fc[10]8d4decc645fc01[5]8b5d0883c9ff8bfb33c0f2aef7d1 }

condition:
	$a0
}

        
