rule Win_Trojan_Graybird_38
{
strings:
	$a0 = { f62fa2e9064f3ca4f0ab93c7dc59b6feeae81ad575f051d0a9ef63377befbdbfd396bb5740f9bcac39b0da46caeaaba7a6d4d42d8d0494557dd60a7c4f2ba5623a1ac3168d3733f5fd5ab06b91fe91f4f3619a5292ccd752d8fcdeb274f26568087a202ea462e7cbd8c1f5e2ea0cf599475c3a283e992a5214c45d }

condition:
	$a0
}

        
