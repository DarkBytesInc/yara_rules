rule Win_Downloader_Banload_803
{
strings:
	$a0 = { c48ec5212e18fad509eb6c9943fc45613af74fc4e9dc2bf89e97d2805f38c2a1a14e6c3a77bb87db8e643a576e77d05d3d1c8d705402ca3f350622799d82dd2ab37e6179c1f55faf7201f03f6dcf20c8b847cb6ed3a7a81c20a7fdbacbab958c276c52db }

condition:
	$a0
}

        
