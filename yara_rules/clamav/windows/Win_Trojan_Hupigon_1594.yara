rule Win_Trojan_Hupigon_1594
{
strings:
	$a0 = { 37c400b3ccd0f2bfaacabcd4cbd0d021000000696578706c6f72652e6578650000000047524159504947454f4e5649505f4d55 }

condition:
	$a0
}

        
