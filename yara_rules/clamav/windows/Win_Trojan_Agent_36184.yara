rule Win_Trojan_Agent_36184
{
strings:
	$a0 = { 3c7363726970743e66756e6374696f6e206e303030286e3030312c6e3030322c6e303033297b766172206e3030343b6e3030343d6e3030312e73706c6974286e303032293b766172206e3030353d6e3030342e6a6f696e286e303033293b72657475726e206e3030353b7d66756e6374696f6e206e303036286e303037297b6e3030373d[0-5]286e3030372c2223232b2323222c222722293b6e3030373d[0-5]286e3030372c2223237c2323222c225c22293b }

condition:
	$a0
}

        