rule Win_Trojan_Bancos_830
{
strings:
	$a0 = { 5375612073656e6861206ee36f20706f7373756920362064696769746f73 }

condition:
	$a0
}

        
