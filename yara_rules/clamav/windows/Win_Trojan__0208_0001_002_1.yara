rule Win_Trojan__0208_0001_002_1
{
strings:
	$a0 = { 33c9e89100b002e88200b4408d96770359cd21b8024233c999cd21b42ccd210bd274f889960901 }

condition:
	$a0
}

        
