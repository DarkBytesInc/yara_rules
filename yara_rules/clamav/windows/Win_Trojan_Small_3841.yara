rule Win_Trojan_Small_3841
{
strings:
	$a0 = { e9830762d8e2e1d0f4069f9a2310df56d8e2e4d00c07ab9c1be191cedc069fc3da676abad66fdd48e94c97446d338e5becf3ce4523db14450c0c1c9c9934e29c97f8ce56d8e2f846ee35f705b5228f2dd4d48e451ba79f9c02e38d1be8e1a495a8228fad5cb9cf45 }

condition:
	$a0
}

        
