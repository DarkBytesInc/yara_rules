rule Win_Downloader_Banload_836
{
strings:
	$a0 = { 4a616b753b58d4cd5c40b241c360fbe87f068e5f01888875b9cbbd022c4c9c5e33f00f7910a425a359c5ef4d153ca80ed0a86b7ee156b207ccb7436f5dfbd471f9443dd45d00778d97bc866f95a140888c0f05c392cea9fbc41fb0ea8e1b7cbd }

condition:
	$a0
}

        
