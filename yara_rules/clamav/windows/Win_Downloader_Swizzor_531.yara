rule Win_Downloader_Swizzor_531
{
strings:
	$a0 = { e0f7bd4dd56bf34ad5b34dd6a4d36ae18e422327aee8cda499661c4da4acf07dc8210587b2fdfe5cb9cd0d95e02611b0ff5c61419486aba586b4bcfb755b3ba61de3e31804d263a96a4f59a02b07b4fa70ffd109a9446f01076d3a38f31b19eb8949e3c5ba17604faba61506cad5ee6e028efa86ff74effe }

condition:
	$a0
}

        
