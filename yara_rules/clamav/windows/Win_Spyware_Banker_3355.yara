rule Win_Spyware_Banker_3355
{
strings:
	$a0 = { 68bc6fd6a84637bc2cf2b7a962e0cae41fe18b826d54bd995410d6580447592c838e18bcb565aae571cf3aeba2edaa9d11115e0e46cb16f4b5003a4d588f2b33f75f30727fb0a0d41481e5b2cd6eb3e2a5f9571fbd }

condition:
	$a0
}

        
