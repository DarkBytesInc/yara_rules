rule Win_Downloader_Small_3330
{
strings:
	$a0 = { 9b6f148ec95b2bccaaa3a1405cdf2fe0b950ce14bbcea1c126342b8ba7cabb116624d4caafeb2a464cae686e44b74a6f4b96426f4c9b5e73d21d95fc59bf45757bb22e604b934f1264b54f7443bf6326ff3734ad43ff7b73 }

condition:
	$a0
}

        
