rule Win_Trojan_Lineage_248
{
strings:
	$a0 = { 26cb71fa414161f619d0a3b1e8ac2648bb6c6931d655e7a3cf622bf287efdd2e6f5b46f9ef8002a45bc1bb72f8446d6f96a0b08a7aafcac898d872aa3c9a7c7bf9f04a24835d42878dcd5c01a25d7fe467b2e23a010f8ed0cdf2b75dfa40840cc34035c8d6519ebb }

condition:
	$a0
}

        
