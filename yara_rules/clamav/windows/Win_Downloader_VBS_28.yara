rule Win_Downloader_VBS_28
{
strings:
	$a0 = { 22687474703a2f2f7777772e616c6578746f75722e72752f64616e2f757064617474652e657865222c30293b2020200a20202020782e53656e6428293b2020 }

condition:
	$a0
}

        