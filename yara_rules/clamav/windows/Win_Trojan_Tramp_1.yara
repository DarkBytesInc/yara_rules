rule Win_Trojan_Tramp_1
{
strings:
	$a0 = { 633a5c222b6469722b225c696e6465782e68746d6c[0-208]6c696e6561726f756e642e68746d6c74657874 }

condition:
	$a0
}

        
