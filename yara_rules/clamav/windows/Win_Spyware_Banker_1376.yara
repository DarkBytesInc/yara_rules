rule Win_Spyware_Banker_1376
{
strings:
	$a0 = { c92511ebb24b33b7dda9921d356fccbd9f95dfb74a9783ec241221805d4fa70a352d2e10e02d727411e3dce974714184152542b577cdd01eff8f126242f685c93337cfa7 }

condition:
	$a0
}

        
