rule Win_Downloader_Delf_1134
{
strings:
	$a0 = { 00de56321e9a06b516658f24c749d10e19ec1bf7c20c6129c3ac3f196fa73cec99c06aa07a8659b228eeb65c3910e1e356927e26ba463fc522e9f3bcdb697da57bd5205a43bed4fee50b8721911bb071f4 }

condition:
	$a0
}

        
