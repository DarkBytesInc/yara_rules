rule Win_Trojan_Startpage_115
{
strings:
	$a0 = { c05a5959648910681c444000c3e92eedffffebf85dc38bc0832d2077400001c3687474703a2f2f7777772e66696e642d000000006f6e }

condition:
	$a0
}

        
