rule Win_Proxy_Lager_87
{
strings:
	$a0 = { 8feee2ed97979beb98fb5657dcb49f7bcf16d0e3fd168afe74e5afb2fa1cce86806bac1931c939b132da439c06bd31a00a37bc92f6c6fe585b3c099388dfb58a7531e030 }

condition:
	$a0
}

        
