rule Win_Trojan_Agent_35425
{
strings:
	$a0 = { 3d6d756d612e68746d }
	$a1 = { 786f626a65637428226d70222b22732e73222b22746f72222b226d706c222b226179657222 }

condition:
	$a0 and $a1
}

        
