rule Win_Trojan_Autoit_82
{
strings:
	$a0 = { 44697361626c655265676973747279546f6f6c7322202c20225245475f44574f524422202c202231222029200a524547575249544520282022484b45595f43555252454e545f555345525c536f6674776172655c4d6963726f736f66745c57696e646f77735c43757272656e7456657273696f6e5c4578706c6f7265725c416476616e63656422202c202248696464656e22202c20225245475f44574f524422202c202232222029 }

condition:
	$a0
}

        