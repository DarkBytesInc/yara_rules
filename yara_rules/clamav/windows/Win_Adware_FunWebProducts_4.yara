rule Win_Adware_FunWebProducts_4
{
strings:
	$a0 = { 5c46756e57656250726f64756374734261725c52656c656173652e53656172636853636f7065 }

condition:
	$a0
}

        
