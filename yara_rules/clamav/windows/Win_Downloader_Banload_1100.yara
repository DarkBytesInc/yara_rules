rule Win_Downloader_Banload_1100
{
strings:
	$a0 = { 6cfe8d0d59ddedc6d0169d70cb1150c614afa09fe0988d01c45a8f629726750185dd69f56d472e869e883354ff61d3c56a6c69e51f8333f80f42a33902fc97a763c64e4192047f }

condition:
	$a0
}

        
