rule Win_Trojan_SdBot_4438
{
strings:
	$a0 = { 8a4331d3dc80b83862839451c0f9f7cad5647d1abb8fd69f3f84c35cfc38b39ac5f43721412be95e146cb2a8f56d3177eb17b60812a1b68a38f1420469b61f6b4faab18af4f2a3556a258fe6d7f6fdccc149 }

condition:
	$a0
}

        
