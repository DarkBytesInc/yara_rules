rule Win_Trojan_C_20
{
strings:
	$a0 = { e800005d81ed0901bf00018db66203b90600f3a4b4a0cd213d080074618cc8488ed8803e00005a754fa103002d0002a3 }

condition:
	$a0
}

        
