rule Win_Downloader_Banload_375
{
strings:
	$a0 = { a1019dc957cdd35d81f18b09f215e16f5a8e300b2daddb749efd47dc6fdd3cd3feed48cafa427abeff9919d76aac33775a1aa7e8c16766b227feb033321d879ee018a04d32a084d2b3c0f7a64edb76671b1e3cf1714f4e6cc698a6905315d997e6ebf737ed2816c823 }

condition:
	$a0
}

        
