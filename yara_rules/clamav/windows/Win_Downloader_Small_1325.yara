rule Win_Downloader_Small_1325
{
strings:
	$a0 = { 5c6d7331dba4951f740a686fcfb010706179a1602ef368d2280dc82464738914f83332a242283411e068746d6c }

condition:
	$a0
}

        
