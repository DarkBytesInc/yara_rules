rule Win_Trojan_Vampiro_8
{
strings:
	$a0 = { 660fbfc11bea6623fc668bc181c186bbccc8662bc139d5660fbbef81b101453337fbd6a525668bea6685fee8160000000fcb660fabd56603fc83e9fc660fabef39f1668bd3bfc3d489df1bd8660fabd54ee803000000d1efbac3d3cb086633fc85f60f85 }

condition:
	$a0
}

        
