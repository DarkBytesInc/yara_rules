rule Win_Downloader_Small_1851
{
strings:
	$a0 = { 5b0c0bd819895418ffbee101e88275a64b1842c5884f5a72c9776a2e3bfdc80a03c5221e2bac8421d3887ef43ea9efd5100edd45d5e83fd1faeb4fedddae215ad0eb3bf309c2d1d0912a9061992cd7431ce882f95135140e8ab0e9fcfe99900aeb1dc3f6 }

condition:
	$a0
}

        
