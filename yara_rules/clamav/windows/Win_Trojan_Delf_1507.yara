rule Win_Trojan_Delf_1507
{
strings:
	$a0 = { 683a4640008d85a8feffffe812f0ffff8d45fce80af0ffffc3e9a0eaffffebe55b8be55dc300633a5c782e65786500000000558bec33c055689d46400064ff30648920b874664000e8d5efffffb87066 }

condition:
	$a0
}

        
