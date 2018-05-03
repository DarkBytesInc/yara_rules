rule Win_Worm_Stration_768
{
strings:
	$a0 = { 32d2a2a8d351d7cae6e6bc1fe876d0fdd6fef5bf778621fec6b272bfd3d3ae464502e3037648faefce91e6bafdde3fcf2349ed417703d82a6446949e0b7ec555d87155348ee6094d85af29602861c6f4ab3b88442e20e2a8b4 }

condition:
	$a0
}

        
