rule Win_Trojan_FraudPack_13
{
strings:
	$a0 = { 558bec5356b8201640005751526819104000e8a90b0000ffe00bc00f850c0000005a595f5e5b5dff2584404000e88e0b0000e809000000e9f40e000000000000552bed2bee8bec81ec9400000056a1804040008945e883c91bc1e9138b4de8894de083f289c1c2148b55e083e8872bc34883e8f7488b45e003423c894590418b }

condition:
	$a0
}

        