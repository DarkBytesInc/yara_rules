rule Win_Trojan_DNSchanger_5
{
strings:
	$a0 = { 537ffc537bfac6a425e958537ffc537bc43cb9ecacfc25e95c53b9ecbcecacfac6ac53d95825d94444bfabacac2f68a021e94cfc9f6cfcfcfc21e944fc53d95853d95053d95453b9a0bcecac296cd9b953d95853d95c53b980bcecac53d95c44b0acacacf553e95027e95097e940de21f3f753d95453b9a4 }

condition:
	$a0
}

        
