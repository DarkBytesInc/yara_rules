rule Win_Trojan_MemLapse_6
{
strings:
	$a0 = { e800005d81ed03011e06b8efddcd2181fbddfe746e2bc0501f8b0e84008b1686002e898ee0012e8996e201065848501f803e00005a754cff3603005983e92a51 }

condition:
	$a0
}

        
