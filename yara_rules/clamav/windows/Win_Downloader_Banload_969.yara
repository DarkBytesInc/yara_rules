rule Win_Downloader_Banload_969
{
strings:
	$a0 = { 3ac62558ab36e028dd2b9eb865d0fab55a814849160095ec991476395fc6932667cdc45a5664da731693d1cb37f3bb47fb01d0dee73b6ffc58c32fac3fb068da786d9e1d8d14f74852ab753125285326 }

condition:
	$a0
}

        
