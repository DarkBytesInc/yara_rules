rule Win_Proxy_Lager_53
{
strings:
	$a0 = { ebc28e5866c68851e88216bd9be4138fb0cd47775efd82442cb6762dbb20f69f2e8a536787cee45e52309749be8517906a5d6ce74532cc50ca7b4fcec672abe8d487484c56b5 }

condition:
	$a0
}

        
