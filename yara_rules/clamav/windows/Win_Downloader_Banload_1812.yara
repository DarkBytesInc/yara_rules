rule Win_Downloader_Banload_1812
{
strings:
	$a0 = { f1e9aad3813abcf6a255f0c87add7f642bfb4a051a63ffe37b5ecb08e5d5dbe3b21ec603309c08039e0c2f55e0f58ff53ad7a11f3d17be399e7e104a401dbfb3ef4c4080918a6f4209645d20b81ee207356550c8189afb03c5ef36a31cd5c416f013bc4751520bb7c7 }

condition:
	$a0
}

        
