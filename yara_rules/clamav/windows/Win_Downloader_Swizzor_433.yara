rule Win_Downloader_Swizzor_433
{
strings:
	$a0 = { bf6f0182fc19295e73155da55f55615acd3fd6ae59802c8c35d2e3c9cb4b6a741329ac276dce4e2201bf8d11c4a1d1631975b058f33bfcb976b5b0d040bd54a582415b1b6fa955c78ec1e1116a4b6bb9fa573afa733ec7b868e3 }

condition:
	$a0
}

        
