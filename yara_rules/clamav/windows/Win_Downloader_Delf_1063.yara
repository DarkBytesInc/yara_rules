rule Win_Downloader_Delf_1063
{
strings:
	$a0 = { f6b42b951c3504490e71bef2f575afaffa1d7eaad36dfae623fd098d0021aed95e669df94ad9db2ce17aaba1b2e169da6c81b4a6142a20e364b40cc5f3d4e28b6f61244756438c40c6c11b29e1ebcb46aa82ca0d14 }

condition:
	$a0
}

        
