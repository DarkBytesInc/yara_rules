rule Win_Trojan_Mybot_5140
{
strings:
	$a0 = { f887bf1c6a0dc3bcd624bce10776adfb284e9f8633b029b2e65ee1b4e7c04ce43b9dabd6f5e0d83a4bd2846d452d78bf9bb256ef5e9dd75a6e8f5f1fbad93ae60cb16c403440ecd69fa0a499d690bd3d2759f414734a9d9890e6e4bd666de7e9a08410aa9508f7c340b368e47361 }

condition:
	$a0
}

        
