rule Win_Trojan_Ciadoor_220
{
strings:
	$a0 = { a8b0a5b6afaf18b0a7b6afaf5315bc1832a830afdfcfa8b04fb6afaf538030cce3e8a830fce3e8a8b03eb6afaf18b038b6afaf51157830ece3e8a8301ce3e8a8b006b6afaf18b000b6afaf5115643004e3e8a830fce3e8a8b0eeb6afaf18b0e8b6afaf51 }

condition:
	$a0
}

        
