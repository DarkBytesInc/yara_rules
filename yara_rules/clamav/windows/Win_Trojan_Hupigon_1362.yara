rule Win_Trojan_Hupigon_1362
{
strings:
	$a0 = { b36cad1b08a442287e83f9665b6ac1d71b59525015a02547e7b19b62c1f747c37ee1cadd64ffebda1eceb56e09ddddf8af1b7862ea81dfdc8b38c8a8244f80d4a28d1a5bc5494f2c516e7d3c64abf9db32be5cf712b4434514714cc4bb4f12349b64 }

condition:
	$a0
}

        
