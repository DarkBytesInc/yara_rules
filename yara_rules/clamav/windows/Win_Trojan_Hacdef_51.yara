rule Win_Trojan_Hacdef_51
{
strings:
	$a0 = { fcffe856a8ffff8945c88d8598fefcff508d5701b9ffffff7f8b45f4e86899ffff8b8598fefcff8d959cfefcffe85bb0ffff8b959cfefcff8d45f4e80d96ffff817dc8ffff000077148b45ccc1e00d8d84c580fffcff8b55c8c60410018b45f4e8d496ff }

condition:
	$a0
}

        
