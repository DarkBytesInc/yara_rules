rule Win_Trojan_Delf_1243
{
strings:
	$a0 = { f2a20876b624f9059b9bfed988d1c6b9b589ce98bfd5d337968c4de8e9e86060a02ffd3a0c7ff01bf21f97e6bb5f369f53b6459e0fc664e40b3961e20375de5b30bd8812fe5c74f0a9b4f7beb9eff40a46ff99773fd2bf9ac16d44b1ed6ef78d7bc9a1c034ee6e535ed69b20533f7721c8b4dbea07f0bb7e5d05b5b24fb17aaf6d871afc90128528f2ae1580 }

condition:
	$a0
}

        