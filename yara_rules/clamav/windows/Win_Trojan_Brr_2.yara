rule Win_Trojan_Brr_2
{
strings:
	$a0 = { 33c0bd007c8ed88ed08be5505533ffc45d24899e64018c866601c45d4c899e09018c860b01b82000c7452453018945 }

condition:
	$a0
}

        
