rule Win_Trojan__0244_0002_001_1
{
strings:
	$a0 = { e88c00b002e87d00b4408d96720359cd21b8024233c999cd21b42ccd210bd274f889960901 }

condition:
	$a0
}

        
