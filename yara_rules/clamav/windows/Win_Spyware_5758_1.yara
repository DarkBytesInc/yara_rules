rule Win_Spyware_5758_1
{
strings:
	$a0 = { 40008d85d0feffffba02000000e8000024c8c3e900001f40ebe88bc35e5b8be55dc300006176702e657865005383c4f08bd854 }

condition:
	$a0
}

        
