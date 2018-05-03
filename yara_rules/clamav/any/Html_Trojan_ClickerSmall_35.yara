rule Html_Trojan_ClickerSmall_35
{
strings:
	$a0 = { 652e636f6d0d0a786e6174696f6e732e636f6d0d0a2a2a2a00558bec83c4f4c745fc00000000ff7508e8 }

condition:
	$a0
}

        
