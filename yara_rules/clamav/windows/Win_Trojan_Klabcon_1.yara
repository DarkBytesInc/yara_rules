rule Win_Trojan_Klabcon_1
{
strings:
	$a0 = { 736f6d636861792e6b6d646e732e6e6574000000626576616e373532392e766963702e6e65740000 }

condition:
	$a0
}

        
