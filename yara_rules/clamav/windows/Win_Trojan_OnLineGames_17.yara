rule Win_Trojan_OnLineGames_17
{
strings:
	$a0 = { ca01990c68a223f721b973ee78097f052024edfcea095b715439a153fa4f8eb51a5ab08b8e994491d367bea59d3d303d1a32d2c776c9286bfda497d3c7e94be53d9a043a4287fb6a674af5825935936ff7e8674f61092095ae5f5a6b98c1a66dd7640326d60514b1a7bebed46009b2a9bc6b2cc7187f0bac92e598b53f4e4e4dc7a3e0b8f84008a011301a37 }

condition:
	$a0
}

        