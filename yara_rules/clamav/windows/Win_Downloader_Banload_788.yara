rule Win_Downloader_Banload_788
{
strings:
	$a0 = { 39a85272336d5b7d32773e61597c0d6767b39c31c368caa09773404a1d640954781de607101a593b585f4226a5cb8964eaba783a0ca5963b6d279d3015246b2acec3061253c39a8c9c9dc45afb4a8e03e22e8b4c0c4d75e77270f655be4a1a607ad14edd75298e8d5f096365fb237b47905ea7bf3d50f6018d4bd770cbcfbf3d079f9120fd4cb86646ddd7e00fb52adc8242 }

condition:
	$a0
}

        