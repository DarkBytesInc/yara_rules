rule Win_Trojan_SdBot_3264
{
strings:
	$a0 = { 68e794e2117c658f6ae353b5d116cb053816f69f98b582f89a74d1aa62b7d1c2163b79fe815dcdab08a5a4fb9ca126723c8a60e671590e9577bd3c8363698b752120638194884e46e3c04d6addfc23b74dcd3f35d775fe69239bf62774a893bfcc299fd9033fdd4c02e2517b7d8221fc8d4911cdb0936315c62ed38776b61abbbd502fa2b5d7181cfad0627ffad284b549f80bc7 }

condition:
	$a0
}

        