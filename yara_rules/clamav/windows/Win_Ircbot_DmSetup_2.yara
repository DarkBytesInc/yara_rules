rule Win_Ircbot_DmSetup_2
{
strings:
	$a0 = { cd213c02730533c00650cbbf6e098b3602002bf781fe00107203be0010fa8ed781c4ce1efb7312161f0ee8570233 }

condition:
	$a0
}

        
