rule Html_Trojan_ClickerSmall_113
{
strings:
	$a0 = { 6572696e670d0a6f6e6c696e652b636173696e6f2b67756964650d0a62657474696e672b6c696e650d0a6f6e6c696e652b636173 }

condition:
	$a0
}

        
