rule Win_Spyware_Banker_2046
{
strings:
	$a0 = { 66bcf252ea4d0ec36ea5750c367395f22c1eb6803b7b05153de0231f747ba3e3876093982b4bb7150b5e4be2e3dbd228030410001eaf76962e75761727d62ee5277564f46dd74a4b7810efe3b92165099158e5954169698c02d559dd82ea764b66975df4ba8cb217bba8e000e4d8631cf511 }

condition:
	$a0
}

        