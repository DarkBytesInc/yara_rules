rule Win_Downloader_Zlob_1695
{
strings:
	$a0 = { f6a1a56a89e1fa8bf0f6ed715abdc0ab8b582911ae64aa0684952878f8bb2866ce90440a51d82642a976b0b103e937d115f1688c7ae8ba263255caa56350ba04cae241fe2b52806a8a90af991c8b18f1d4add68cb14fba371529 }

condition:
	$a0
}

        
