rule Win_Trojan_SdBot_1807
{
strings:
	$a0 = { e4203e1280466a90f1ba848a2cf949500a1f8269f6db03ec4a82b11ae2b912b25ff3c3420cf3622d09dd6a367ef271ae149bf53e7d20521206a6f35a21cea97a6ab59df75d9ffec4d1c2a33a947eb0a1d59af34e5cef5c2a4e37ecdbdbea38 }

condition:
	$a0
}

        
