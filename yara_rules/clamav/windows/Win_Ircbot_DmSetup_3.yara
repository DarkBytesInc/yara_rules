rule Win_Ircbot_DmSetup_3
{
strings:
	$a0 = { 213c02730533c00650cbbfb0078b3602002bf781fe00107203be0010fa8ed781c47e17fb7312161f0ee8570233 }

condition:
	$a0
}

        
