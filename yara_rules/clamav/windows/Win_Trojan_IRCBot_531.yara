rule Win_Trojan_IRCBot_531
{
strings:
	$a0 = { 49f10bc65775723f43abd317da88b3c29775f5f6d4af045328462332eefda5cdb6fd066c3f4719586f63b89b5fb0d8a73cb13bb9bddabe83d6b3243addf1d0db2517645d653147bfb478e51bc03eb6fe8e596a3c36e2f000b52ae29096689652cca81e7e737407457d31cd072463e9f845b5b57a1dfe46176819983e6035e72f98fabf642f864f8b050d421fd4ac6f59663942a31354 }

condition:
	$a0
}

        