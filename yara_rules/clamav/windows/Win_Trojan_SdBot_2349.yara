rule Win_Trojan_SdBot_2349
{
strings:
	$a0 = { 4ec35c01fb00d00a0c62715bf5611bd05c5efee04d796305efefd148ea9b15d82bb48124c2c44584d2a50991b5b72db5080a08194605e4a8f9afbbd42ad396145ae70b96fa784cc68a65c9557577ee4c21ba7e59a7 }

condition:
	$a0
}

        
