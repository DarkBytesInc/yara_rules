rule Win_Trojan_Bancos_1789
{
strings:
	$a0 = { ad4730e5bb61f0a999038690feb7f0473f0ed8d676319203e52c5ce72fed483e65349d3b9c23b61b9061a7e8d0e1c79c602f762da2dada48340a5a40271e73d1dde93d8488be }

condition:
	$a0
}

        
