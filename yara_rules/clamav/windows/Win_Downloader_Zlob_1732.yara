rule Win_Downloader_Zlob_1732
{
strings:
	$a0 = { 38898290d1709240f54d435cb2670fc9fb95bd19251a72b963cb663ced808a94444e8acf5ff02262632304f6aca3d55b9e4f2c6a6b25266ee094d870bac4c386bdb24b2547fdfb7fa1ed9c220b7b }

condition:
	$a0
}

        
