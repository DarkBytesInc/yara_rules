rule Win_Trojan_Lmir_12
{
strings:
	$a0 = { de86091b9ab8643064b2a409b8b419a78ce7a0539075eb5f76e8f68db7ba796d614b65632041056956df1cbf54645b20c6f3d2b53900bdadc3f1bbffffffc9b1b6bec8edbcfe204b5632303034a3bacab5cab1bce0cad31f5261e3d98cc6764d80300b436c2e2dffbf90e3664c6f }

condition:
	$a0
}

        
