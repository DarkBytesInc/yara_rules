rule Win_Trojan_Bancos_1955
{
strings:
	$a0 = { 5431b83d2213bf8311f0493d95c33572b8a75ce6b454d14b36aebaad90501bb7a7d2f46ed7e3f127e804ba29b70fbe842fc7dfcee08573219fb8e089a720a5ce0704a85ab9a05a02cf7d792548a7e4d011a19712b75c22c7c6d3 }

condition:
	$a0
}

        