rule Win_Downloader_Swizzor_406
{
strings:
	$a0 = { f90cd3bd88a180722ecb8b6d186ee6dc3d08bbbb686a45e4469498ccf4ff484f1a256a598861b31c1e56cc7f2ededc24bcc385099d05c7739c98b20d3af5bc46504e813bfd842522cff7881a163c0cf76b0916ddfe3ceb256a44 }

condition:
	$a0
}

        
