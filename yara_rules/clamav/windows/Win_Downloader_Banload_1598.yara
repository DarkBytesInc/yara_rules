rule Win_Downloader_Banload_1598
{
strings:
	$a0 = { 0460170c00efbefdf6fd898d8a9e9892ace80f5b03d403d682314ce85449324d93542434fc9ed473c600a62caff3e9c7cec6c1d5c49b0e980d064230cd198fdbfee1ee7f19d481015a3a7c3d7bf1b93652649041065e6a0e904106197e1212410619641e0a0606196490020e1a1964904116f2feea62904106b6de2ad5 }

condition:
	$a0
}

        