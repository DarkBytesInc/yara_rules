rule Win_Proxy_Lager_71
{
strings:
	$a0 = { 27a6448b825eedcf356738314670d484c6a9005cbdde2f331d69a07a9ef7ac737ad1be8699753cb43cabd7b905c112c0c90a511f0731d8bf93e8efedaa90ec8ad05da7daa9df }

condition:
	$a0
}

        
