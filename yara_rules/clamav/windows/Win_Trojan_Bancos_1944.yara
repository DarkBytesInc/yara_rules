rule Win_Trojan_Bancos_1944
{
strings:
	$a0 = { 5914d45feaeb8fb2ba3eb8da3f3ca7363ab4228ad550774f42132d3141d67a2659d92f7db479bba41c7002c1f8ce7e9de635b1c0b1f41392fc7c4bec652339376590bf3bd1d989995f6e81ccdbdc000ea6fea7aa6421a7363c4c }

condition:
	$a0
}

        
