rule Win_Trojan_SdBot_2342
{
strings:
	$a0 = { b9fe07af3c9903e559e1831e908b1a766e197ce350d00400fe82869a16fbccbb60d91c8954abd579dc1ba910193028bc6b26bbe5bdb4ead0595d731a4e018cfa15f6de5574f461a3cf5d491d5a5331d08a871f704a }

condition:
	$a0
}

        
