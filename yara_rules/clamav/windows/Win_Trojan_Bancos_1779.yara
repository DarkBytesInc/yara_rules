rule Win_Trojan_Bancos_1779
{
strings:
	$a0 = { fb03d4a45014223d48663e661b8448aef4c8c10f3aa51f2e8817a723e8ea63d764c13042d7f69853a1e2ba92a218e82ba9c86381be380d84462cfe46a0080483d98cbebe9e99 }

condition:
	$a0
}

        
