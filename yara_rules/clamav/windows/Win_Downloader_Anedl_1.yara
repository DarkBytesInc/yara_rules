rule Win_Downloader_Anedl_1
{
strings:
	$a0 = { 61746846726f6d41626f766500036f66666666666f6666666666666666666666 }

condition:
	$a0
}

        
