rule Win_Trojan_Mybot_7748
{
strings:
	$a0 = { 752850ef5f4681ef22389a99041703dcafa4e46f2e1728d9aa797b01cef5780efffd1ac99eada0d6e29160caeaa2cc0c0606a500b955a6420c3f6dcbaddc3f1b4ec1a4587330cfd7cbe8eaaab19ea50649c33fa16f53b38fc04199b207af8cff556976f9b183 }

condition:
	$a0
}

        
