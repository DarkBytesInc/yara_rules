rule Win_Downloader_Banload_601
{
strings:
	$a0 = { 5868f3ad89e731a177aa8308dc90ad93e2c127f4477f927a742a78dc2484394f9db978a83e716ac724c5075fda761f91f3bc725ab73385e0167f62370b6b018e4b6c4625 }

condition:
	$a0
}

        
