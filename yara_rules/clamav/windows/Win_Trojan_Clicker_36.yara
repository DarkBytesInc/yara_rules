rule Win_Trojan_Clicker_36
{
strings:
	$a0 = { c25af4725d30076c3d2de5db4d56d5044ab55c329816421951db6e89e8305c12c9703119ad83796c09fadae664a74a30226cca107fce88dbd440e5da3071fc3907f83c8a50282a170aedb641e50ec286 }

condition:
	$a0
}

        
