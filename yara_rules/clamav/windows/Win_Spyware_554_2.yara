rule Win_Spyware_554_2
{
strings:
	$a0 = { 94e19e2d41deb4deeb3a5fae2cd36f1116846ec38a5f83185ff7c8aaf30f00d63c6ea78320ef8fea9593b3e146939416fcf547544b08dfb560a82ea9eee7519268c92d35c9c2b288f8420057548a }

condition:
	$a0
}

        
