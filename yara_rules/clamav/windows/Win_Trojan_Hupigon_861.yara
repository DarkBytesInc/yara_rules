rule Win_Trojan_Hupigon_861
{
strings:
	$a0 = { b46b9aa59ec99cacf74d6bf2f304abb3909017207a823c79ad72edc810867a3beeffdca8db075eca5a964ac272909d31c4e17cd0fb44336a1e6c94cc8c3702e70c52f4cbf1264f77aa15019d5b53b4080357b74262a5f26e294e369c5d1b18 }

condition:
	$a0
}

        
