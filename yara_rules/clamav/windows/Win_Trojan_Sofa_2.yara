rule Win_Trojan_Sofa_2
{
strings:
	$a0 = { 20004a002800e00066006f6e20001401bf00646f67003d0020008a00bf0044000000ae0827004a0265 }

condition:
	$a0
}

        
