rule Win_Trojan_Lineage_414
{
strings:
	$a0 = { ca01990c68a223f721b973ee78097f052024edfcea095b715439a153fa4f8eb51a5ab08b8e994491d367bea59d3d303d1a32d2c776c9286bfda497d3c7e94be53d9a043a4287fb6a674af5825935936ff7e8674f61092095ae5f6de388da0c2e5c3a320f0960a5646582fc72c170f085ca2d21c0ca07e159e38db0fc94db339c8b0812ce017175b007710f6e }

condition:
	$a0
}

        