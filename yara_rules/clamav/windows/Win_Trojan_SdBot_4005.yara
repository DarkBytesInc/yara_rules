rule Win_Trojan_SdBot_4005
{
strings:
	$a0 = { edfed3ff6d8cc40a5f59a75d4b319fe2697ff92d25dbb4ef51629e8ca0e3cb27232e11638f6b5da00c4af1999dcc19947d58dc33349673367f90cae12ffd1d6c794bac12318e3738d2dabda1f9ef2a52adf91c91a02e2b5c33c0dcd66f3d96ed2119f12e }

condition:
	$a0
}

        
