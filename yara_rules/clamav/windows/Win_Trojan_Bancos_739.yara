rule Win_Trojan_Bancos_739
{
strings:
	$a0 = { d2ba737389ff7354430d93f4233600fbede05dc110fa428226b1749e675b644a630e05088817cf0ae19f953cd815bbf77d8bb13eadf88bf15463de6d84ba907a06e2badd0a21428f4ec6fc50 }

condition:
	$a0
}

        
