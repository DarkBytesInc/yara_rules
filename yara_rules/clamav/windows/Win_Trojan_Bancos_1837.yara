rule Win_Trojan_Bancos_1837
{
strings:
	$a0 = { daf9927830306627f5710800d204b93d9dcb187f22d84803647ca35547a7fac1cfdacde78ce6968b4f8ecd968f50b914b1bf9936352fffb1e1fa0c56cb660844dfe78d628680 }

condition:
	$a0
}

        
