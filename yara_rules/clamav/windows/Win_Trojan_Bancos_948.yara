rule Win_Trojan_Bancos_948
{
strings:
	$a0 = { 1662e66dfe95ebc25dd87a8eff5d63c4ea912c3444bfe410c14e856f41c3a0da657d74b19ccca657bb36b564b13b394235642aa8884fe8d7e1cc37ba02510e63feaf61b2f1e745623a358de7e4ec5876ff9a688b74 }

condition:
	$a0
}

        
