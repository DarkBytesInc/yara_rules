rule Win_Trojan_Bancos_1752
{
strings:
	$a0 = { 948666e7d67da0ac0a74d58d9eb5c19e49a5a7789732ac7bf4e7c21e55b2767c9e06a2b45053ae17f031e3c002e56367a7e7a2219c35730999512d829a1a5de528bb32de1adf }

condition:
	$a0
}

        
