rule Win_Trojan_Hackarmy_31
{
strings:
	$a0 = { afc05a6f6e654ce930651e75702e1e78b83f628374736d6664f76ffb1c83238b337006076772616e643e5c07746f758f98442153004f4654574152455c034d6963726f73916674ebffa83d3d77f81c4375725e65ce74569dfe37 }

condition:
	$a0
}

        