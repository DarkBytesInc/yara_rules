rule Win_Downloader_W32_10
{
strings:
	$a0 = { e2ea7fb16573612076312e352e50ff09a62e06202f6c20414c4c20bfcbff06fb18656c647320776920562949442033d5 }

condition:
	$a0
}

        
