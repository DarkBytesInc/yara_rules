rule Win_Downloader_W32_89
{
strings:
	$a0 = { 6a736f6674076f6d006f70656e1b00defe7ffb6d6d6672690f64006372656174652073657276022e6578fbdfb6ef0a75 }

condition:
	$a0
}

        
