rule Win_Downloader_Delf_459
{
strings:
	$a0 = { 4000e846b9ffff53e848c6ffff33c05a595964891068967f40008d45e0ba04000000e88ab6ffffc3e988b0ffffebeb5e5be867b5ffff000000ffffffff0d0000005c696578706c6f72652e736372000000ff }

condition:
	$a0
}

        
