rule Win_Trojan_Bancos_1001
{
strings:
	$a0 = { 7734496b2e78b5d9290fcf8459992c287bd9777fc23819d58ae137e840e3952fcd6f3d9fc79c0253b192fe808134fb5594f8af1af176410f5a7d5682f7d3cfd7 }

condition:
	$a0
}

        
