rule Win_Trojan_Bifrose_310
{
strings:
	$a0 = { b78e4aed3578251993ed43b9b17461d3821a495b79486adfb6db8ded45c26f0f6c33850d3839f7414ee5cf6db22b4f0ed16ab349b061d110b159a1ad956ff3894625b5192b6a0513aeca09329fb5b53ec96dfd635ca5b41e35819dcf9153a2955ab399fda6cb2e2992e1b967c69e5a1ea9d84a3d5c55811da95242192d0b9955510800ce479f424eb5214645 }

condition:
	$a0
}

        