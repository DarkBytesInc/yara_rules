rule Win_Trojan_SdBot_1286
{
strings:
	$a0 = { 054d7214128a8026064c2524d456db0e020fe08503cb311d0075d539894ed9b06200d823124b1ee1a11c3e0f1700496e5072901148a0b83176000633325218071309032d674944d12c87c045474d4f0f4ec32846c04cd613a6100ff658e176800481c4fcfd00ebe55fed7d6a98b73e852000fe0a5057e83fcbf4c60084051c0e2b1a10fd }

condition:
	$a0
}

        