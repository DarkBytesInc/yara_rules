rule Win_Downloader_Zlob_1590
{
strings:
	$a0 = { 5e93cce6c5de3e6711821ffcba880d87c73b3bb1b06b40b888b5968afffd98257b97e44077a6d3a7246d6f01b71eb7402f92f2b3f9eddcf9f9a03d2875d4e56e063314afee1fe61f9d15c1dc01f1b575c9ba7873248a08686a22bee5e91e112f49e7c9ed3e70591f03eea26959b1dd6cfd15d87928d63515503f54520e8e3342bbe649f27c33d2ca033171dffde274c33732a55cfdd5 }

condition:
	$a0
}

        