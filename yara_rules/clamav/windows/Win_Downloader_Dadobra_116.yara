rule Win_Downloader_Dadobra_116
{
strings:
	$a0 = { 5fc4a08e01ba9aecdc9b11599672fd904106117e8a860c220e657e8ab633c82083b2ae9a8308421c1e4c2a18f1cd2036feca310103e04b94d2a9af19125be6681b00205aff4c232a0470060db65cdbce763fbda3342326f5e622260619441c2a1e1964904112767a0e07081908e7e50c61d52e92abdf93c0e3a000669c0cc9a2 }

condition:
	$a0
}

        