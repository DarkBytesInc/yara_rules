rule Win_Trojan_B_14
{
strings:
	$a0 = { ba01fab8455992cd1687da87da87da2eff363a010e92921f2eff2638010000000200000000000000000000000000 }

condition:
	$a0
}

        
