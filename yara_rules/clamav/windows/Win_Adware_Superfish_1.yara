rule Win_Adware_Superfish_1
{
strings:
	$a0 = { 4d6963686967616e311330[0-50]4772616e6476696c6c65[0-50]53757065726669736820496e632e }

condition:
	$a0
}

        
