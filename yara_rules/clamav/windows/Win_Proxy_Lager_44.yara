rule Win_Proxy_Lager_44
{
strings:
	$a0 = { 73a89622f31a038856e2aacce1db7f3292cc93871215475f69626830c9d5e7794a4beb70ae6df9854dc97bb7e81790bad17d55c31db6161cd38d9fbc4754a8ee7e2cab8904e1 }

condition:
	$a0
}

        
