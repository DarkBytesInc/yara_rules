rule Win_Downloader_Banload_544
{
strings:
	$a0 = { 569ba0415b6ea094e12fa555e725cb35197093c90d986c38cb22c63ca17f92f7e527d1248d31b328e4577a7c235471d2c39c56a7747c129dd823491f77003846511d48af14f9f5c17f96fb35bb38759da7ba5cb8e8be36cf517589864e3eacabbef7ab6301ffa805634805aae4440766a97e224950e0a1835406d4f602e96f30c88befa58d061d88767cf3e9 }

condition:
	$a0
}

        