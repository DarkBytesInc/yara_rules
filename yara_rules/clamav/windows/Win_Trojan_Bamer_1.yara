rule Win_Trojan_Bamer_1
{
strings:
	$a0 = { d25e249ea37ccb8050930ed86895a6844b5dacb626b95193e0d212ab4d24b76b06bb74c76abf20f76936ba0cc66af7914735a75c2663b557c9539a3b2eb3b1ab9df1698b64f8c765202a05ba4a96ffb8 }

condition:
	$a0
}

        
