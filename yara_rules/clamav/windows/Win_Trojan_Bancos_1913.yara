rule Win_Trojan_Bancos_1913
{
strings:
	$a0 = { 68c6eb2c0385f1cb9f12f66ce768b5cb0c2d486c27da2e310873b558bec50418b44eafe98fc465d1fc1ab9a74aece3b5373111808e0a10a4c7959e76d660b4e047ba0bb5cabd9b1bf1f715e37d8a2cae62ce3b0d44bef8d32cd0 }

condition:
	$a0
}

        
