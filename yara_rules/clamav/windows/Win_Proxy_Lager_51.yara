rule Win_Proxy_Lager_51
{
strings:
	$a0 = { 3521674aa08bc2b209cf758bdc31069c30848645e45cfd32cb335d85447ade1b48733a3d5a86d999d8b47c4733b9452df6c089e6b51f47dd3cbfd3040bedea7c088a90b143da }

condition:
	$a0
}

        
