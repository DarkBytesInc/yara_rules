rule Win_Trojan_VB_1438
{
strings:
	$a0 = { aa33a4f9811d620238c8f0d9e40ab67490a7809d602f7cf09f241d0f49d4b4e7be8c2a25d570b9dc357c777d1d1d151ae356cb7cf6176758de0289426a996fdbe9221519926ad05eaa72d89f4b7e4b14eeacde1154668c5d0c3d53e8c2d7658381660e1e25932799841195407ccff5134ea9db13d88e075cc729c51fd4eb6b85ecf14834b63cc3c1a68bd8d4 }

condition:
	$a0
}

        