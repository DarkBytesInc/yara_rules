rule Win_Trojan_Riot_24
{
strings:
	$a0 = { b419cd2150b40eb202cd21ba8901b44ecd217309ba8f01b44ecd217244b80043ba9e00cd2151b8014333c9cd21b8023dba9e00cd21722693b80057cd215152ba }

condition:
	$a0
}

        
