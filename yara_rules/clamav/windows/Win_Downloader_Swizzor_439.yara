rule Win_Downloader_Swizzor_439
{
strings:
	$a0 = { 840eddeb931bd3efde1dbb3f295c2a21061fd668aa86e8f42531cf1b131fddede92030c6537f546e9615aaf4141929567dd208f20d3fdf3c5b72dcedb36beb1d7d4027883ba263f8d7d7a2d30c189de44900cba1a2424fee7c39 }

condition:
	$a0
}

        
