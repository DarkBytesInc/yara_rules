rule Win_Trojan_SdBot_2413
{
strings:
	$a0 = { c239806d02134fc66672384a5b73afdeda568a7e4b5b6feb6d7d41054c084d025205a4362ab5d1523d71a20d10f30221f3ffacb5cf4c26bc78effffbdce7ff7f7ebf87c9937dced92f6bbfafbdf6da6bad7df0207e1d2d052653c7ae5c387f1e0b677b299c55abe04c1b0967f53d70fe }

condition:
	$a0
}

        
