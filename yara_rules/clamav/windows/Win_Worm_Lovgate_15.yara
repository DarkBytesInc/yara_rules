rule Win_Worm_Lovgate_15
{
strings:
	$a0 = { 5a38b58f61d5ce38564a3013dbf199abdbe26a6a67a3aaea3207433173fb736f95c72f8f9bb02227a0bc0ed62c6b2bd1b65c72528ce1c0d8a9356a064c2318c1 }

condition:
	$a0
}

        
