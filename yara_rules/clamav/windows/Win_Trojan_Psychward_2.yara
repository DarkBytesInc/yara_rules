rule Win_Trojan_Psychward_2
{
strings:
	$a0 = { 45fc000000008b7d08ff7508e8b4000000eb2433d28a1780ea308bf04e508bc253bb0a000000eb03f7e34e83fe0077f85b0145fc5847480bc075d88b45fc5e5a5f59c9c20400cc558bec5657fc8b75088b7d0c0375108b4d14f3a4b000aa5f5ec9c21000ccff2558204000ff254820 }

condition:
	$a0
}

        