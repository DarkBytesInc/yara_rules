rule Win_Trojan_SdBot_3130
{
strings:
	$a0 = { 7b2c681474cc8dac8b96f4bb93be3b27b3cd854e8be20aa8f403b3142960630097e3ba54ddae05afebaeb47b1f1ccfbfb7fd33f30f1ec8015bfc24f3afd702879c174a1556a12030caf5c41ab0c0a20a057e7b350ea73bb099c5d3063abc7c7e8dd2289a21a80cccf529e8625aee602223df344405084435ab825bb15241f1e0f761f552eed359f8ebea8554f4d82cd8764229dabf89 }

condition:
	$a0
}

        