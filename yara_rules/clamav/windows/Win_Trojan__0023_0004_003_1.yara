rule Win_Trojan__0023_0004_003_1
{
strings:
	$a0 = { 8becc7460200405d58b90400ba4a08cd21e90001803e6208407411803e5c086b740aa14a08 }

condition:
	$a0
}

        
