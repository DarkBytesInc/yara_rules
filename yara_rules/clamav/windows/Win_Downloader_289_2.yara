rule Win_Downloader_289_2
{
strings:
	$a0 = { 4e8e980c898a5a77857b716f191b9694a07e827fd5b6242445a2528f90d3be263e5e58ccf55e1a37bd3b312fcaf251f2794a40ca85e7b4e2e203580855239be995eaf03ee52b6713fcfaa3efc53b }

condition:
	$a0
}

        
