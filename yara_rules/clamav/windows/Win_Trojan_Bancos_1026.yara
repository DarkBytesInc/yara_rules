rule Win_Trojan_Bancos_1026
{
strings:
	$a0 = { d5f111847931be0d818a919a6958127dff7fba13b5c57ff562f065e4d57bec22c4231d7003751f39032d1e2897e3e692dd92c25eee95507c28f6c2c58127b34b92f3410b3f85bbd59b8c936d9e613ae8d0317b4ac6755a8b }

condition:
	$a0
}

        