rule Win_Downloader_Small_731
{
strings:
	$a0 = { 63687488703a2fe277cf022e6c6f1865e26e797379631c6d2f69cd616740dc333452300b063836352e838f47617a }

condition:
	$a0
}

        
