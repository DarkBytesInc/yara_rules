rule Win_Downloader_Zlob_1533
{
strings:
	$a0 = { b341740f5da643d7a5c018b5207f3991440436ba81ee89d3fde667811c4fad1c63222063c4671ac577cbf99c1a101eaf12d7462e555d88c2e5cebc73cb6dc9d8ade5e5197494f571 }

condition:
	$a0
}

        
