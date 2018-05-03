rule Win_Worm_Mytob_115
{
strings:
	$a0 = { 6848a880985d98ee2f146c445c1b2598eae1ef051bc87b9a5016eec4d0ecd9257d536ca383f3cb8f500f19aaceb58b5eebbe403e089afda4bbdb9bfbdb320a833c3dc0be885e70233eee992df7aabc43b0d02d9d0d4701777d79c6a976293bb9f057ad188d1f32a6da1d9761105c5e22 }

condition:
	$a0
}

        
