rule Win_Downloader_Swizzor_588
{
strings:
	$a0 = { bb3479552ef5e379c22c25a685cec3e54b652ebf611ee63df66a0da6ad95a8e43af4391bacc8fb62ebbe1a24144e61b74f2b31916959ce2b0d2fcbe075b6b4e92846251bbe4645e8ac98155a40ffc4df5bba1732302627a44aba197b5bffefe11d95e5212e3d1afc52 }

condition:
	$a0
}

        
