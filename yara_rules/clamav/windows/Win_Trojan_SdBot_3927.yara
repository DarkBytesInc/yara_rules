rule Win_Trojan_SdBot_3927
{
strings:
	$a0 = { dd152e819abc7991b9d15b37ef7b4a6a71b1dbd698fb3f078566b5d3a0cac90b688e79eb9a9432beab650d3295bf1462a0d62b30b3e918677eec2c76816a070d88bb63a4c75b8b3e63e7a2ac99a3078a18e1d42f350f8c8066eba53d }

condition:
	$a0
}

        
