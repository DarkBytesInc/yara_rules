rule Win_Trojan_Bancos_1163
{
strings:
	$a0 = { 5babfa2b9743f5e49cd8a8b9cc88ff22c2d9c0ec3d4b35a6e27d106bd1469b1381420a505e629899dd93b06f67a1d1859fc85db5fd39a638cf31348bae1af87a865ca191d5f9c5fbf42e2d3ab10eab9f0905222d6d3be1bc9710ce75edfe13 }

condition:
	$a0
}

        
