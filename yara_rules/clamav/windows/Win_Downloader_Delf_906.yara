rule Win_Downloader_Delf_906
{
strings:
	$a0 = { 31c3caf6678ccb0a9b460d6f4f8346b3a76eadcf1cc748cea11e456d30a52c7ed2af389f1a9761fb6c7187225df0a1d75549dd74bcb2ef3c2cfe4c6c8df33852437c118cc22427203ac3be7425fc131530d513c47a7c43a0d92df528d3682821df79eee7 }

condition:
	$a0
}

        
