rule Win_Trojan_SdBot_3863
{
strings:
	$a0 = { 63e9b1e3868b0629ad5caddc7b30569aeb964e80770d8dcc169d1c4a0feecebcf521df3187f5577eae0e01102827621f0e5764f9d3c1d11986a98975b165ee3bf14ee03b09b8f9f51779839a47d54818cd0ae1b5a7 }

condition:
	$a0
}

        
