rule Unix_Tool_13250_1
{
strings:
	$a0 = { 68622e2e2e89e733c088470357b08850cd8057b03d50cd804733c9b1ff5750b00ccd80e2fa4757b03d50cd80 }

condition:
	$a0
}

        
