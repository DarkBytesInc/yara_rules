rule Win_Trojan_Startpage_241
{
strings:
	$a0 = { 4100c3e9d7fdfeffebf8e82cfaffff33c05a595964891068063741008d45e0ba04000000e8b203ffffc3e9b0fdfeffebebe89102ffff00ffffffff040000006e63635f00000000ffffffff1f000000687474703a2f2f766166 }

condition:
	$a0
}

        
