rule Win_Worm_Magistr_13
{
strings:
	$a0 = { e909000000310a13c61bc0c32bc7050b207c07e80b00000048e909000000312ff9731a90c333c13d7d277c07e8efffffffc3 }

condition:
	$a0
}

        
