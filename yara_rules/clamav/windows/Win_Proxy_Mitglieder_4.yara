rule Win_Proxy_Mitglieder_4
{
strings:
	$a0 = { 485454502f312e312032303020436f6e6e656374696f6e2065737461626c69736865640d0a0d0a00002c00202c0d0a003c003e0043433a20004243433a00546f3a200048454c4f2025730d0a005253 }

condition:
	$a0
}

        