rule Win_Trojan_Hupigon_354
{
strings:
	$a0 = { 2083c52b99a946c918a8bdbb4701089a1155617d30a0a0d14c24ed6c7c320b36314c9f8ea3b2576006cb7470f38369c138362c14b1f49deae58247094b6ea962e0b1c29ab2e0908ed2aee68867db40ccdb76d85c39b860200a99fdbc2ea37cfffa60bec54af8d18e41258ed1b664d57ef3b295fe72a62f283928cfb5db720063515f704c39732b73c0f00bc5ba36b749a610dcbb49e4 }

condition:
	$a0
}

        