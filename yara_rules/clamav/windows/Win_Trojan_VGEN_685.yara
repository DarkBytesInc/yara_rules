rule Win_Trojan_VGEN_685
{
strings:
	$a0 = { fd909090f7d79083c600f5f5bb3001be570f87ff9081c65ede90750070003137464e474f434383c6007f004f75f0 }

condition:
	$a0
}

        
