rule Win_Downloader_Delf_1066
{
strings:
	$a0 = { 4a12914e8b57cfa874449b9ccbdc09edf5448fbc3f3c45e388a25e9f9db13eb58a0c36dce4b2485a226cc5a432e71cd09cb7cd798bad7b8d9ce3cd3edfaf8faa657790c746983cdfd2b19563706d05f39fbcf94bb4 }

condition:
	$a0
}

        
