rule Win_Worm_IRC_25
{
strings:
	$a0 = { 726970742e696e6922290d0a536574207473203d2066312e4f70656e41735465787453747265616d28466f7257726974696e672c2046616c7365290d0a74732e777269746520225b7363726970745d22202620766243724c660d0a74732e777269746520226e303d4f4e20313a4a4f494e3a233a6463632073656e6420246e69636b2022202620506174 }

condition:
	$a0
}

        