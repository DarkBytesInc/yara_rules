rule Win_Trojan_Bancos_1945
{
strings:
	$a0 = { 727e455edd06c00ca7749a87bae5c72fc0614fa1f542559098e3e64a17335391f1d6da171b78dbe7a13b48dfe5203ffe71fedc27a2c0bab0383e4f1183fa68f8543798e61fede0159d5ae302bba476afdcdd42e099bd4595a8dd }

condition:
	$a0
}

        
