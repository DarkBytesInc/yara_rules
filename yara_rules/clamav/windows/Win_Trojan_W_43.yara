rule Win_Trojan_W_43
{
strings:
	$a0 = { 47fc0d002020203d2e6d70330f84930100003d2e6578650f857e010000e89502000033f6b9 }

condition:
	$a0
}

        
