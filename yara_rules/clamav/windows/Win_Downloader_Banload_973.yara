rule Win_Downloader_Banload_973
{
strings:
	$a0 = { fe324023ef45c119a655e01f96631e44774f0bd13cab4196472a8ecee07ae54b20bf492248afa53d948c959a5405bc15176dff9b7b8b620fea1f91b8ae20e02a4d7176e3995649a501b0d24f03fa }

condition:
	$a0
}

        
