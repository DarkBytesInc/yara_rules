rule Win_Trojan_Feebs_23
{
strings:
	$a0 = { 3d7265706c61636528[0-4]2c22??222c222522293c2f7363726970743e }
	$a1 = { 3d756e65736361706528[0-4]293b6576616c28[0-4]293b }

condition:
	$a0 and $a1
}

        
