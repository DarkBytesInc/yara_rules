rule Win_Trojan_Delarm_3
{
strings:
	$a0 = { 2e8a0434ff2e880446e2f5cc2d4619fe44a5bb41d0fed174fb7c39fdfc2f1d09c42c8bfa4700b332de4bc3cc3645c7fe14f2889691998d9a9a8bd18d9a98ff32deafa77427af4bbf46f7ff45a9fe14f7adbab8babbb6abcb32dea77427af4bbf46fdff4591fe14fdf2f5 }

condition:
	$a0
}

        
