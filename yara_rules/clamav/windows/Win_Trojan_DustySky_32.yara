rule Win_Trojan_DustySky_32
{
strings:
	$a0 = { 673a5c576f726c645c7366785c323031352d30372d3135204e6544207665722035202d206d657368616c5c4e654420446f776e6c6f616420616e6420657865637574652056657273696f6e2031202d20446f635c6f626a5c7838365c44656275675c4e6577732e706462 }

condition:
	$a0
}

        