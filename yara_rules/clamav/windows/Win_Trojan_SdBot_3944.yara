rule Win_Trojan_SdBot_3944
{
strings:
	$a0 = { 901f037d720fbf3e3c8ac3887a7a76b943b3805f829a138f19d98d354fa07d33dc4ef7d0e172e6c5ee202d32614414a66dbf5180dfda08f3a84cc6cc0238e9fdc229a5be0c81c7e64c714297f2c74c3e3177bd4bd6b5b7f1d35aa8fd }

condition:
	$a0
}

        
