rule Win_Trojan_Agent_32683
{
strings:
	$a0 = { 28225100838c1832456ab9bd06caa328ecce43e690d4ab089776fe4fe236e2046edce7a50eeddccf1aa87e0a599446e2d15254fc10b3c4d58dafe8880ac8907fc876e6443555cbfc4c895f769261cb00205033cf6c63c814f459fbe295a74caca4cb9e0abc33fd19d9d459e8a44f77ba2e98d93d03de1d9acea250b05028b7e0dfe30a3ac7016f4b6f71fe1d }

condition:
	$a0
}

        