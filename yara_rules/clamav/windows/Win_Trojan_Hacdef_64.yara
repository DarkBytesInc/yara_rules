rule Win_Trojan_Hacdef_64
{
strings:
	$a0 = { 06faad0929fccfb64e929ff752d0eed492f298c643bcd4fa403624c3a1d684d75a24c669cf556939b31a02d6ba929ec6628e2577a2bf4e73ae009ebe138a9fe6608e2577a27f4e73ae029ebf938897e650c3ff236af6b357d6b6 }

condition:
	$a0
}

        
