rule Win_Trojan_Bancos_1434
{
strings:
	$a0 = { 91adf87c8878a5adb1241d258340db42917d44a9bed021616e1b702fbc312820d91f55d8072a6e32b0b33b3ac5daffca7d8b6a00260fe7832b2a88fed4fff49890dac59691b22811c30e3a78132618accd0e15308dbac08e6721d66ab5d5b54f }

condition:
	$a0
}

        