rule Win_Trojan_Bancos_1887
{
strings:
	$a0 = { 074171c4f3d21fc7670761bc841960ac111c296bf6d98f03a8ccedcf987f9edbff7d75eb686405f1e999045a668925ec02962fa14fa5dcc3b10a08cd4e41c29b93128924285a }

condition:
	$a0
}

        
