rule Win_Downloader_941_1
{
strings:
	$a0 = { 4d39b7ddb823b11a06a08197fdb9f4dd70ef10b288ae402ad222a271f89cea01a680712adc49eec978087982e3c3447764e7402feda4fb7465d7e5e352fa6cf56c80baa01cc8500df5f75cd88e41ffe2cd84cabece2b0f4d8ad8b5a5 }

condition:
	$a0
}

        
