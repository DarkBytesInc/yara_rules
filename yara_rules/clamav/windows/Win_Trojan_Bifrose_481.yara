rule Win_Trojan_Bifrose_481
{
strings:
	$a0 = { 0900008d2b0c22861ba34dc7bbeaeeb6bf5022c5d58c04639e5f2ab0783977f8fde6707acee7e28eaf6243a70ea74defed03f3402ed9192790b330a756e8146c4aa62e600a172bccf206d3d5d1b9dd3573bfea1f1117184b2313 }

condition:
	$a0
}

        
