rule Win_Trojan_Bancos_1529
{
strings:
	$a0 = { 663f62d17c58652c35198c023d05a08950298d1e92a11655a6e3c8183b4c2381eba3683a37ee2ec12af803703ff3b6a563406faea8e9a77cf380cdfc2723eaae5c810822d7615c74eb849b382a4e2f4a60ec2070458cab4258c0b6d866753e8c0afc1f0ac62edf2914198185f744c30e15705bd06dd5e8fd4a2d6c01b764ae7f4721621e5e5a7c2048f89747c4d0ff1a9c3355caf978 }

condition:
	$a0
}

        