rule Win_Trojan_SdBot_1938
{
strings:
	$a0 = { 3b2a6120ce9e01cb86cf769cbb49ca8ece6730d0ada222194f2e5328875298caf87907e9ae7d8b34786fb4308c9f4af0bfeb3818b70b85945279ed057c9621e4ce3dda7dd9ece68e2ebb1a46e4b9c73af95b9ed7e03335bcd23722f432397f }

condition:
	$a0
}

        
