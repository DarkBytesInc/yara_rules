rule Win_Downloader_Zlob_1481
{
strings:
	$a0 = { 59b7cddb1b4ea8afe7e0456aca6d4a4b73ad4cadd4a978ad02463badeaf9c56523b65eedf8aa37cd93c584c2af12c89c0bcc0de47f0a3c9763edf47809794e4e21da792ea21996eeac2471e531eadac1cddc9defffd46724daeff8fdcdb3cea45e91d680a0 }

condition:
	$a0
}

        
