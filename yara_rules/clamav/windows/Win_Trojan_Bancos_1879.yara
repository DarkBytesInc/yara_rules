rule Win_Trojan_Bancos_1879
{
strings:
	$a0 = { 504089b38c5ddbab6a817c6363bad8f07bd1e3ce425420182351d820e551a758e28cd3855f636237132490dc0a0b8928f38f793e73fa9a5ef2ba6a0a2a9d4ac1541e8ae36904 }

condition:
	$a0
}

        
