rule Win_Downloader_Banload_271
{
strings:
	$a0 = { 4b194b72433300e29af670f7e808bc0d0d21e6990028da229606a8f60adff65bcea41ba8bc08d2838d625b8b83a0059e34586a97a8283d2d995c9efeadb9ca895374ccd623b6e423caa3e61df03f3391622fd0066fa938da41eb }

condition:
	$a0
}

        
