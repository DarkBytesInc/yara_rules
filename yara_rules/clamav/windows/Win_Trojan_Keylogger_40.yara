rule Win_Trojan_Keylogger_40
{
strings:
	$a0 = { 6a00ff350c300010686d1200106a04ff153420001085c0a31c300010740e8b442404a30040001033c040eb02 }

condition:
	$a0
}

        
