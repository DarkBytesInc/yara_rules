rule Win_Trojan_SdBot_1808
{
strings:
	$a0 = { dd2addaa42adc6a15d515df8ab48a8873cd9965899cc996f669a1c13dd5d8aa8f4aa42ace0aa0c701c29ca97e2d81ab37ae693ddf7fb0e65e992f1440fdbb726993357bca04338db65974e91c10ddee4e63e1d9ba398f778d2e245a3a9dff3 }

condition:
	$a0
}

        
