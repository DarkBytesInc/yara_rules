rule Win_Trojan_SdBot_4037
{
strings:
	$a0 = { e097abc3710f7e26e7fc753f7ffff61714b2de935ea647f020f409a4d863270ac8aa6287360134fb26c949bd6e356b945fdb90429d1e9be2eff4afa54dcc9a77664f8d718614d04cb804cc6f328af4990745bc45c3e7 }

condition:
	$a0
}

        
