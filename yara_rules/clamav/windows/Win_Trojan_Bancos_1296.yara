rule Win_Trojan_Bancos_1296
{
strings:
	$a0 = { 15ffccfb4edacdcd847b24f8cda6323719b7c50120c345b9a0a36a98dcb700390617e4ae4eae140640b88f43189f410bc4559b741fc529b022389f10cbbf088e036a108ecd6f55af9b46a0642f0b8a17f415509b }

condition:
	$a0
}

        
