rule Win_Trojan_Vgen_86
{
strings:
	$a0 = { d8488ed8c60600005a812e03008000812e1200800033c08ed8ff0e1304ff0e1304a11304b106d3e02d10008ec01f }

condition:
	$a0
}

        
