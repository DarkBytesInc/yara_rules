rule Win_Downloader_Delf_279
{
strings:
	$a0 = { 637861676662a524afe46269746463fdaf0442ce81703a2f2f62796573df5de84d8287736d192e75e03f25e26f6c2ed12e62722f }

condition:
	$a0
}

        
