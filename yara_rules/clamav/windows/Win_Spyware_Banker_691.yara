rule Win_Spyware_Banker_691
{
strings:
	$a0 = { bfb56867525da30714cc1e788d941ef301795a2a0a9b840e3c218fb4ffe52cd4c42f1e92cdcd8a737388401db779bddff42c79f3a2ded95671ad3a880067f5bd24b067e3d543f2e15dce9a1cb0015f585d306c879a5ba60aca5145262e7d0d7d1f4b37f9eb421317ba1f25762fb032320b0a279ae6db5ecec63cb235d2e975bdbb4cb15f9fa88769929ac241d2b70c4a7beb3a332d5c }

condition:
	$a0
}

        