rule Win_Worm_Bobax_17
{
strings:
	$a0 = { 8e6970e9d0beb51079740c19a62097a715e057b9b7a8bf4a1a47f3022f5079badf04895e08fda101f2b5316efbef8a7de911baab31029b609b516464c72a06845a5f02e80d514e84080da9bcfa064218fce7ec3103f5e581aad521900478398d1dee0226ea30769e341ccfee897b76f2 }

condition:
	$a0
}

        