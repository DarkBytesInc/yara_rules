rule Win_Trojan_Small_5287
{
strings:
	$a0 = { 3f120dbc578cb6faef238bce2fbcf7a277bfa2ba7280bb10ee93e30a4526a40d57a4b6faef108b2cf2bba23db3d4a12f13d4a1d0f7cbe2ba4e1a0016487ff91157bcb2baef25abb904f4b2faef0ba2d02bcce2ba7aac0dbb59dff824efbab80efffba23faf30d5452cecb2faef11a292747c17 }

condition:
	$a0
}

        
