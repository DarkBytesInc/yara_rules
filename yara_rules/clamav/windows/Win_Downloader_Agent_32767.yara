rule Win_Downloader_Agent_32767
{
strings:
	$a0 = { 24f9ffff6580e62580c19fc68527f9ffff5280e61dc68521f9ffff43c68523f9ffff6980cdd380c9c655b2e883ec088b852efcffff89042480e2a280f6bb8dbd1ef9ffff897c240480c5c1ff1544d501105d8985abf9ffff8b85abf9ffffa380cd0110c685aefdffff6e80c69ac685aafdffff65c685b6fdffff0080c170b145c685adfdffff6980cab8b671c685acfdffff5780 }

condition:
	$a0
}

        