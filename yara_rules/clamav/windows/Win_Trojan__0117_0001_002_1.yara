rule Win_Trojan__0117_0001_002_1
{
strings:
	$a0 = { 86ff0105020089048d96f501b90500b440cd218b1481c20301b9b505908dbe3d078db60801e868 }

condition:
	$a0
}

        
