rule Win_Downloader_Banload_469
{
strings:
	$a0 = { a97550e6db61dcdf6cea5d65153a00aae3289ed52dd794b2503ffcad93f7480b33f0b2b19f75ab1a289296d0668beabfc7064e65604959ec16f2ac89f27e507919d49bbc574308a6e129bacf4c7795729336f71b }

condition:
	$a0
}

        
