rule Win_Trojan_VB_1632
{
strings:
	$a0 = { 7779737866726400000001000100b071400000000000b0c34000ffffffff000000003472400060d9430000000000b8a80406000000000000000000000000 }

condition:
	$a0
}

        