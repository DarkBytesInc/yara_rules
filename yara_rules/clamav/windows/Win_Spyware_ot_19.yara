rule Win_Spyware_ot_19
{
strings:
	$a0 = { 51be0fadde685763da3a0247ed377096a7a6fb2a3e4bcdcdf51f3351e22e6d0bed0a5cc4e6cee703861f6b2e6338cb07d7fa0d808bde652ce8c24d2698c9df2d3f3ec1f8ca5d6e965c687fbc4aa18a49e35c0e8b98ab08f16e96694b777f3d8ea3c341c4993719e5 }

condition:
	$a0
}

        
