rule Win_Trojan_Defma_1
{
strings:
	$a0 = { 6f70656e55524c3a0076616c7565466f724b65793a0073686f774e6f74696669636174696f6e3a3a3a0072656d6f7665416c6c4f626a656374730064696374696f6e617279576974684f626a65637473416e644b6579733a0072656c6561736500687474703a2f2f6761792e706f }

condition:
	$a0
}

        