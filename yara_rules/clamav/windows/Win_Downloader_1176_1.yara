rule Win_Downloader_1176_1
{
strings:
	$a0 = { cefa4d2cac08684e23493e66ebcfd6692db6a3b60e5f217d6e47964328e69a8824fcee8f2dcdf6b98627fcc13e1d226f6f6eb6ed6c7329db2e092b7ab6f223db67d929f72ab21e3225f17eafccd7215592f2cbafcad5104688576a99 }

condition:
	$a0
}

        
