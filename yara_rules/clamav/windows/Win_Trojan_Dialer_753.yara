rule Win_Trojan_Dialer_753
{
strings:
	$a0 = { 6f632573746f722e6c6e6b0000000025735c4c6970257347616d652e6c6e6b0000000025735c5858 }

condition:
	$a0
}

        
