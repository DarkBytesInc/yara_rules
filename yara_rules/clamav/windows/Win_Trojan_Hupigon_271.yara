rule Win_Trojan_Hupigon_271
{
strings:
	$a0 = { 369dddca6ec3bff5824d1cd74b74194d859394511b2a64d33d020b7a9fe2a48a67000b74cacf1a3ad4deda567b542761d596ad8e78211c6f88aef0202612675c2bc4585e10d7180566f8bf60d7eab4afd75a1f890fb0cdf65a2c7ab4d7ca357b5d7ef47d6332c6af3c5a5b903fad }

condition:
	$a0
}

        
