rule Win_Trojan_Bancos_2077
{
strings:
	$a0 = { dd30e19d097ae5e52e413e225983d616f289620eb7bce216e8d647c20dc1b6a4f0a3ffa6e4319a3914b2ad40b3c7db1e28a0fc131bdf04ee3957e58b12bb5256b8506df9657fdc6b2b4a739393268fd496b5f8ed3004b9ede99d }

condition:
	$a0
}

        
