rule Win_Spyware_W32_20
{
strings:
	$a0 = { 880d51a7400084c9753683c2024875e9eb2e6a4ae8b4d1ffff85c00f95c0a251a740006a2ae8a3d1ffff85c00f95c3881d50a7400084db740755e83efeffff595f5e5b8be55dc300 }

condition:
	$a0
}

        
