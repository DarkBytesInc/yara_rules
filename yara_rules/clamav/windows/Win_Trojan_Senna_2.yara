rule Win_Trojan_Senna_2
{
strings:
	$a0 = { e5bf30cee0cfdfbddec25c43b55cfa65cbe966159ec77521ee2124809f1a49dfc81574dd7b08308cf966f9003f0530d8c7a443a75d0df3ecf82e65599d50106b5be6f7b30c8830f17ddffb5cdbe354615f2933f66cf6867b0315c51594edbed7cca471b1 }

condition:
	$a0
}

        
