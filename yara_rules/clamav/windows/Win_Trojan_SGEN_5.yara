rule Win_Trojan_SGEN_5
{
strings:
	$a0 = { b847018ed88ec033dbb403cd108916fffb5f011e069a05002d09071fedf809b400cd1ffe1a87c1a38401f38201fcb951007f0ebe0f00bf025df3a4f44e0d0df453f4fe5bf4a4f4fe660d1bf4f5f4fe72f4465ef4fd7e1a1af497f4fe88f4e8f4fe8e16c6f4395ff4fda3bf8af4f382e87f10f1db }

condition:
	$a0
}

        
