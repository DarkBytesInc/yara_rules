rule Win_Trojan_SdBot_3923
{
strings:
	$a0 = { dd6d503f0705accb4c00fbd681d6d3d04092d3eb02bb9936a0720230b17aa54a31684300d0bdb4dbacb0a91e50c276f2a4f10b18e07bfad8cb17d9c7802fc65cf4fcee2005de16a39b03dc182d35d45bddb62a524de5314a4381fe6f }

condition:
	$a0
}

        
