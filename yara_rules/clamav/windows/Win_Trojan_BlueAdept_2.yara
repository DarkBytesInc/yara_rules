rule Win_Trojan_BlueAdept_2
{
strings:
	$a0 = { 4aac24a1c93486174799c685bcb496021874944c3447191ac9348e2ab71b1a4b0aa609b09adc165df264081cb72c3803984ce3421d091c68491bbc4054981e34 }

condition:
	$a0
}

        
