rule Win_Adware_FunWebProducts_2
{
strings:
	$a0 = { 46756e57656250726f6475637473506f7053776174746572426172427574746f6e575757 }

condition:
	$a0
}

        
