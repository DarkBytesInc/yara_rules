rule Win_Trojan_Delarm_2
{
strings:
	$a0 = { 01b9e5032e8a0434ff2e880446e2f5cc2d461cfe44915541d0fed174fb7c39fdfc2f1d09c42c8bfa4700b332de4bc3cc3645c7fe14f3889691998d9a9ad18d9a98ff32deafa77427af4bbf46f7ff45aafe14f7adbab8babbb6abcb32dea77427af4bbf46fdff4592fe14fdf2f532 }

condition:
	$a0
}

        
