rule Win_Trojan_Startpage_381
{
strings:
	$a0 = { 1c200010b0015f5e5bc9c20c0032c0ebf5ff2520200010ff253c200010ff2528200010558bec837d0c017516e84e00000068043000106800300010e825000000595956ff7510ff750cff7508e8ccfeffff837d0c008bf07505e8390000008bc65e5dc20c00568b7424083b74240c730d8b0685c07402ffd083c604ebed5ec36a20586a0450a31c300010e82400000059a31830001059 }

condition:
	$a0
}

        