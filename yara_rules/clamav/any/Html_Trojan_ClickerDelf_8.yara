rule Html_Trojan_ClickerDelf_8
{
strings:
	$a0 = { f7a53e554fc9e26e37264fb5ffb7df7e703a2f2f6632652e6863773a6c642e636f6d2f41582fd9ad05f06d6178641016746d674b11fccd0b61626f75743a62326bf52082b000003213e461862a97eb03943d34b778d800e01f1368212426ea17 }

condition:
	$a0
}

        