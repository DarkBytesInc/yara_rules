rule Win_Trojan_Muldrop_1
{
strings:
	$a0 = { 782a721d3e8e9444121245e41895860fd02b19035362a36a45179a89c5305b9e5e307faf068256069793e7c10627bf271614f3a2e2c68fad8bbebffe9105ec88228b72a9128aed565151a2d389c9f62fa29bcfcd7c268bcce2f5ce69f55c3bdf8900def6fea92ee8cf565949b0927f173c7ae1c2c3 }

condition:
	$a0
}

        