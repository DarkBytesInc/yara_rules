rule Win_Spyware_Banker_4689
{
strings:
	$a0 = { cc02a8c569b1cf036f3b374124d677859d947e6a85afac4f46c2948959ff3f5f9db3bf56de20931e510144f90ee9694c00bef971c9f9daa79bb39efe5def72482e8b00b9b2dccf8104ac446aee045cf511c6f4a0bdfbbedcf4142b5a2c79ae9ad136 }

condition:
	$a0
}

        
