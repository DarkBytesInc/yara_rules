rule Win_Spyware_Banker_3516
{
strings:
	$a0 = { 1be2d54c3dea8e6e2441e2d139eb789876053b27ac6429b85d1051b574797fbcbbe6551cecdcdb142d94d3d0a7d7bb564d2656c63fa6988575a521bffcf921ccc2fad72cfbdcfa8a4353536146e957d19ce7bac0c0090c837209 }

condition:
	$a0
}

        
