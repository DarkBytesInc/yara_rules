rule Win_Trojan_Bancos_795
{
strings:
	$a0 = { 218ee3a289b76165b3569ac36fb3f0025eb5f1047a90f60629f5a34aa69c8ac1b4290711cd901367b31951213b1f34a064fe71eec058253a4ad4c7db70b48b7a05b9b18d }

condition:
	$a0
}

        
