rule Win_Downloader_Zlob_2267
{
strings:
	$a0 = { 24a4b8ed96539eba008298bf6529b6b1b5e0f90e1c87bf5e6b5cf55dc79614d67a38a9ab11fa52e7b7e071a8dae72ae872bbc295a307ed8cdbcce193e70e12742db1736af7b5b268940fa7c08ce83e4dac91727bd4039fdaf758 }

condition:
	$a0
}

        
