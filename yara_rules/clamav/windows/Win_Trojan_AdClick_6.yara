rule Win_Trojan_AdClick_6
{
strings:
	$a0 = { 167beb0ea4250eecddf347cc7b60040b08a7a893f5add30e98880cbbef483ff11591145524056ef2dd48a7656009f5f143c267908336c4ca11d3bae2b8d1c39cbaa4ccfde2efa0ae96955dbeda64726c230913a1d5bd132625f120e8ad76fbb1d3eadcbffebdcbd2aab14b6f5a863b7fb951e050b605a74eb508ff }

condition:
	$a0
}

        
