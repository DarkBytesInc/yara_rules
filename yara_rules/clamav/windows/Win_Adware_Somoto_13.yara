rule Win_Adware_Somoto_13
{
strings:
	$a0 = { 74657220496e7374616c6c657200fd9980006269636c69656e742e65786500636f6e }

condition:
	$a0
}

        
