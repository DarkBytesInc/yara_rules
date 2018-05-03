rule Win_Proxy_Lager_86
{
strings:
	$a0 = { 8ff3fa6d8c025e882f5915b83d6c83e1c47db2d9d7adc8c2f3657ff154a7d258799081b8cd13971d70ba78b37d25233c1f5cd7a829a0cb0801eeb240b7a255db85a0a28e }

condition:
	$a0
}

        
