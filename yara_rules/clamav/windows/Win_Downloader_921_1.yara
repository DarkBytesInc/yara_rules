rule Win_Downloader_921_1
{
strings:
	$a0 = { cae631a758ee2c3bac1e38770a1c8d7de4df0d24aa2a781face1cedeb26514d1d876b2cbea407bfc122cc60603686ba2b011188ab58dcd0e0b1cc8d93fd128b71590ffe312f1566cec56e5ce791d040db527d5f66c18e9f326d42ce1 }

condition:
	$a0
}

        
