rule Win_Trojan_SdBot_1857
{
strings:
	$a0 = { 70a17add3e84f4ec78bdddececb5c7752d5e46b9cee529dc8776cbaf7511eaf92696edc4e4c7cf63751549dd86ad97b8f0ec7519d9f69f4fc8b8e0f6ec9d1ddcee41ccec01498bdef2cfe509a4bac8a671c2c749c90570c573a6a44f83f6be88c92a5be55c8bec0a68c6f327c35d1372 }

condition:
	$a0
}

        
