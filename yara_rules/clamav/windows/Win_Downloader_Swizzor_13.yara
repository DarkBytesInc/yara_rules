rule Win_Downloader_Swizzor_13
{
strings:
	$a0 = { dcd32d2f26c308ecd66ff991496c25f83441f7a62fc95886d10f57f5c8e4054359d6cb78a04c5545c9d4d27c396974c39a201d0d5c21daf30998b55e97e2f6e9ba6d2e9f4721b68cab5b5af3cff94d3ceedcf9be7d0be1de4f562ffa35bddd449bb43ac05e6d194988e0 }

condition:
	$a0
}

        
