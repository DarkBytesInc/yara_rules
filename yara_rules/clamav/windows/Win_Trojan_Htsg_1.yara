rule Win_Trojan_Htsg_1
{
strings:
	$a0 = { 1e55e8c40786688684d809986a76fcb30430eba26e8e7f61106381d5714586f8b17857c782cb47364df9487721 }

condition:
	$a0
}

        
