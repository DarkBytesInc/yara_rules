rule Win_Downloader_Agent_32875
{
strings:
	$a0 = { 4e62047f4842b2249e354d70dd9ed42ff0bf4308cd546e0a07f1c718c7909e9c1bb00386d545266ac715817ae9ef4609a9d0479e645d40f60ab3e87658c0 }

condition:
	$a0
}

        
