rule Win_Spyware_Banker_3420
{
strings:
	$a0 = { a9f4256ef97581a12e3fa7f942ddf6626864fb45d54429a3369aa604ca9819764bc726d35a9977068fbace86dc97622cbee92db708aaf67e1ba6a8f3275e8b1831aa7370d8f0e3771fd7ef }

condition:
	$a0
}

        
