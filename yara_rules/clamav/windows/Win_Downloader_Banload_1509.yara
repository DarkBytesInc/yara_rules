rule Win_Downloader_Banload_1509
{
strings:
	$a0 = { ccbca6ddb0adc5f7ef10e30a3fa07ea9898969f6f9be4550e62215de14174b9e0bf3a2bcd73ea4ba41581667fb0b4feff47bf1ba1f2118a3e933a08acfe559cc28840cedbfaf263ce9ef7bc247ddad62899791902379dcd758da709a7bfba6abcc740fbce99d846958e851dca066900560c7ff841048 }

condition:
	$a0
}

        
