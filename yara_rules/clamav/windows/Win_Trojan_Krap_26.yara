rule Win_Trojan_Krap_26
{
strings:
	$a0 = { 0fc1ff0fbdffdceadcec47ff1508200014fdfdf7d0f7d0f7d08d05c1a30cfe8d008d00fdff150820001487c066b9891266b9557a03c903c9fcfcff1508200014c1c9f6fff1f8f85bdcd6f8ff152c200014dcdcf8f8f8f7d3f7d3f7d38d356158d3e7ff15 }

condition:
	$a0
}

        
