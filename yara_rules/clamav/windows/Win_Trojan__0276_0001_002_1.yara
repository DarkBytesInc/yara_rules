rule Win_Trojan__0276_0001_002_1
{
strings:
	$a0 = { c9e89100b002e88200b4408d967a0359cd21b8024233c999cd21b42ccd210bd274f889960a01 }

condition:
	$a0
}

        
