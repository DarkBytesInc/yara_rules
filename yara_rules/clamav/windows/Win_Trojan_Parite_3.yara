rule Win_Trojan_Parite_3
{
strings:
	$a0 = { 90c7bd9408bbff53845056037b09c8057bc1c2aa09bb50bc5f4500547d9c848f836357d9b38c50d96386feab0916e89ef74400d036301202a1c94d9ca7c98596 }

condition:
	$a0
}

        
