rule Win_Downloader_63406_1
{
strings:
	$a0 = { 837c2408017505e805009882ff7424048b4c24108b54240ce80500530a59c20c006a0c680001 }

condition:
	$a0
}

        
