rule Win_Trojan_Hupigon_809
{
strings:
	$a0 = { 3755bd964f256b5cd73924b30e6292f21574b77ba2ba47d5991cc1788acec9585cc89ef5e10d012265e321d9170da0333c9203ac5c90f62c16b0211aa8a1dfb59e5befbe64bc2150e21b3e2d2cc870b9afe3ecdfc6661f9b7e315add26a89d }

condition:
	$a0
}

        
