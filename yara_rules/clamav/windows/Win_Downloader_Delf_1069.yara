rule Win_Downloader_Delf_1069
{
strings:
	$a0 = { a2ff9be5c05aa3ebfa7051bc9cc41aab0d2ce363e95d3558db59d3354ec8fbd8ff5a9d89a3562ed1fa4539fa311cdc621ecd41cd1626ac2741e9fbe02f1941ddfabc242fc11e1bdb629c1a3f088aee5e694cfbff1d }

condition:
	$a0
}

        
