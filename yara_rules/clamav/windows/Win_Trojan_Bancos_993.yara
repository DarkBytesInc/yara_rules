rule Win_Trojan_Bancos_993
{
strings:
	$a0 = { 4db961b41278e7576a0689ede443ea656b6328ba026b4d0b8246eb484d595dadecacf023bf5e3b757d751348e00e9dc3724d871f8c14dc0fe0bf990025142871c06f50bcadfd6f0c1e9efbddd46592787e418075d9 }

condition:
	$a0
}

        
