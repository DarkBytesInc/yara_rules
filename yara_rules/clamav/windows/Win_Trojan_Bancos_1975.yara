rule Win_Trojan_Bancos_1975
{
strings:
	$a0 = { 4aecc81aed7d3754d87c22fefa7d8bbd7c9c590ebb662cb9b6b8747e34f21d5cc20e533a86f474da24eccef7a32aeec888f39e4196ca43abcb3e0876c7ca21f91f3a1feff2798a1f980a9405c32153a5cd6ef840a6b6f6acd1e36fb139e60d7b9a877e5fb0078b80066c3a6d4f04 }

condition:
	$a0
}

        
