rule Win_Trojan_Convert_1
{
strings:
	$a0 = { cc30f631707cca68973287967e2377c2d317dd968cf4a69b320aaa32d56ebb474f77c3acc6785456d5bb084f9351412cf0100b492015d5efce41cde7e233584fac51e61e115ffdd71c4583b95a6d2f55 }

condition:
	$a0
}

        
