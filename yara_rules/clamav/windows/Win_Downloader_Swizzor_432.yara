rule Win_Downloader_Swizzor_432
{
strings:
	$a0 = { 4fbc2352c5542442a6825b19985f3fc57e79d0df12f3881466224b26b60f032c3dfbdc5f739bb862e3db061cad441b2cbb7a82e8474e2b0dde7e4fc1387ac6f0cf69478a8bfc79691bdd5e23e3622bcd06e97cf71349d5ca5086 }

condition:
	$a0
}

        
