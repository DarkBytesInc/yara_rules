rule Win_Spyware_Banker_6273
{
strings:
	$a0 = { 25f271aa92dd1499989bca2532a30d46685623c88605a929dfe93aeab1099f3f9c96b2102a312353ff97f9a41ab328e9c76acebe067172ba7a7d41b27f06f28b1db5af5ff8a5cd31cb643e3f8ede7e2f12dc1434a7eecf83a9296dcdfed21f }

condition:
	$a0
}

        
