rule Win_Trojan_Stantinko_2
{
strings:
	$a0 = { 7777772e3031307265636c616d6566696574732e6e6c }
	$a1 = { 2f6d6f64756c65732f6d6f645f70726f78792f70726f78792e706870 }

condition:
	$a0 and $a1
}

        
