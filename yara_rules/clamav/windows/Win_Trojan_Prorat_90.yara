rule Win_Trojan_Prorat_90
{
strings:
	$a0 = { 4d6735cb1edf249e3f72f683c138dcb140e64f9e6474cabb222cb904a9da5df389ce679e714041bad9f5ffe2abfb3bc5fc8b41988a69c247b35d923954ef6c73a5972bb0329be5433a82d6d868e1099184f2a78e24ba4b834c6ba943cacbff92a938070e }

condition:
	$a0
}

        
