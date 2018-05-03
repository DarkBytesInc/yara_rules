rule Win_Ircbot_DmSetup_4
{
strings:
	$a0 = { 213c02730533c00650cbbf010a8b3602002bf781fe00107203be0010fa8ed781c4be20fb7312161f0ee8570233 }

condition:
	$a0
}

        
