rule Win_Downloader_1267_1
{
strings:
	$a0 = { 853ffbffff6380e1a380c9fec6853cfbffff7380f6cb80eddbc68547fbffff0080f2bb80e98fc6853dfbffff79c68546fbffff7880ee0480c9c0c68544fbffff43c68545fbffff7480ce65c6853efbffff6ec6853bfbffff4180c6a6c68536fbffff7280ee8180e920c68543fbff }

condition:
	$a0
}

        
