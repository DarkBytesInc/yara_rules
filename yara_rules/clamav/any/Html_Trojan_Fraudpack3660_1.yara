rule Html_Trojan_Fraudpack3660_1
{
strings:
	$a0 = { dcfdffff898dd4fcffff018d44feffff29c981c0db00000085c9763a31c109c183c16329850cffffffff85a8feffff234dcc8b8524ffffff21c84129c1018d04fdffff298dfcfcffff214d982b8d34fdffff29c101c1098d9cfeffff294dc4b874000000 }

condition:
	$a0
}

        
