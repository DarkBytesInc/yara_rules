rule Win_Trojan_Tepfer_60
{
strings:
	$a0 = { 8d3d1421400083c7928b376a5659c1e6108d46908b044803f083eee333c9330e84c9742251b01c2ac87210582cc0770b68003040005fe9e1feffffb837204000ff50016a7c59e2fefa000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee }

condition:
	$a0
}

        
