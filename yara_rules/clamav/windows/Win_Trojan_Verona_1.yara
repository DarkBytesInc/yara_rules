rule Win_Trojan_Verona_1
{
strings:
	$a0 = { 74656d31222076616c75653d222c633a5c77696e646f77735c74656d705c6d79726f6d656f2e6578652c223e }

condition:
	$a0
}

        
