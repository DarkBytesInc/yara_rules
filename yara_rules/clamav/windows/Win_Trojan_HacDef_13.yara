rule Win_Trojan_HacDef_13
{
strings:
	$a0 = { dab82927ffd989f883f223a17195d6408c10baf39e4764d35057b62a9e27913e67698fdef685a37dfd4eeca2f2cea3468f9b41c7dc5f754846107894da1df210ea8aceeb90d88e08d6629017a854738e764e6f2bdf930291a0d8742cf172fde49324e691e3668baa3778575f26dbc90b08fe5ba553519f31 }

condition:
	$a0
}

        