rule Win_Downloader_Tiny_110
{
strings:
	$a0 = { 5f4865296ba00f3e78534bbd234e464c4a4d059c4e537e3633c174217c7e657a3d9452424a463fac6e1c1b6c737a06b66b050d185b9220235e5d40483d900e435153478e2d4d4f03474624f54d575157589b280d5e43415139944e52115550934c237865616505c612185b5a53fe69500e490a4c31902014 }

condition:
	$a0
}

        