rule Win_Adware_Lop_167
{
strings:
	$a0 = { 6662295432f0fefa0af44afd44ad1e96864f2e1f1dbddc9cd1b511d279d9e988465e1af3143a4a1c68d5a03bd6ed31588568629aca271868e3183dad1d33521f55fee3fdff8c40d5df1e111a9fe682d15cb95b777fbcad3b55d41269f87d999d8085 }

condition:
	$a0
}

        