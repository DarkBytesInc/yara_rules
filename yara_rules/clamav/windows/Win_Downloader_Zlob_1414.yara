rule Win_Downloader_Zlob_1414
{
strings:
	$a0 = { 8e2621f315f6bbcc1b678e63af671c4b756b8fd27dd38b441a0c5d1f0e651981422ae8a02ae7544e1a2c7d65a2116897d103ce0c5cab4326ebfb28f2c6218a1849e0f0da375699b08e4754280c2727d0e79743c9f67b2bacddb09234aecdf975d0303bd236b3b3facd1e1883a15c1dc4cd6e1d1081f08b03a36b9b3a142c6ddc659a80c59521537792c49c3e3cf151e718e16057e7df8974cd22ab7355e8 }

condition:
	$a0
}

        