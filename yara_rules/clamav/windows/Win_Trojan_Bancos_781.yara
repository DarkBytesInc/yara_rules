rule Win_Trojan_Bancos_781
{
strings:
	$a0 = { 101ea2c0b37014ffe22a6beac8a03c9d993e1ebf295f13f0b906430484eb1250ed956dc6f0c7dab13efa0c42515520931cf0a7a7ba61cecadfc62c394ac7b4df3fd7a68d09a5f3313cb0071da9a3243ec21b67a5fbf05fc050dacef93e93c06736e4f274411a60fafefff04d6ef742eacf84487d698cd414b57eee73b173 }

condition:
	$a0
}

        
