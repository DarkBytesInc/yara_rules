rule Win_Trojan_Ehu_1
{
strings:
	$a0 = { dd50281448455990eea5181b6aff3c1c387ffbdfd9535988f134424d8d47366303dd895c2436e8cae77a1195063c6a3e7d7b782b3634b90e2e46c538ff570c933dde036dcb0dfad8f88f1dc16409d8ab76097ac6c3147c65406361074ad88f7a36780932a0122f0c63095f6c6357420ef7101716da6a04d651e857e0fc1b70a324878e73187d }

condition:
	$a0
}

        