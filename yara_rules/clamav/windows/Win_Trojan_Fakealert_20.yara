rule Win_Trojan_Fakealert_20
{
strings:
	$a0 = { fc179f92e8d70535e374bfe196d51f2a5b64e907eccc98dd2f17d43ab444f3939dacd2fffe1fbaf28f3ea0c9db926758ebf3d5a8c1749a39fdc3af5b933ee4e12f382ecbd72a01ceb2ac27c575f418c2163cd0df458016d2eccc91aa8b2385880a7dd4c7 }

condition:
	$a0
}

        
