rule Win_Trojan_Bancos_2025
{
strings:
	$a0 = { 7ab9cae0bac8bdc242616b5d3664fa5398b418f3c58b2b31a1ea1c66452d81889bfa0d0302d86059f6e4f6779f9e47a798258d2a046b07fda1e63b8b3b8a648be443978c4675ded81dbac0af1e67cbeb6ae8291ab1b874bbd73c539d1f0f61f6a173ef2cf65cae29d5f0d1f5f3a6 }

condition:
	$a0
}

        
