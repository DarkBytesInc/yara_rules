rule Win_Trojan_SdBot_3841
{
strings:
	$a0 = { f37f7698e6edec3cd347b5e8e769a9f84de24be36c6385d3dad929c04b8dd5d45696dd59548abacbca574e60bec5c4142dc24e45e3a8bcbb0b224542f7b61fb41db2b0c5fb7eefac36376595a6a50e6dd7a4a1a0281f79e4e09a241d53839493fc52 }

condition:
	$a0
}

        
