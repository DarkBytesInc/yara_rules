rule Win_Trojan_Delarm_1
{
strings:
	$a0 = { 1101b91d032e8a0434ff2e880446e2f5cc2d4680fe44009441d0fed174fb7c39fdfc2f1d09c42c8bfa4700b332de4bc3cc3645c7fe14f4998d9a9a959cd18d9a98ff32deafa77427af4bbf46f7ff45abfe14f7adbab8babbb6abcb32dea77427af4bbf46fdff4593fe14fdf2f532de }

condition:
	$a0
}

        
