rule Win_Trojan_Upero_1
{
strings:
	$a0 = { 257573657270726f66696c652500000064656b73746f70323030372e69636f }

condition:
	$a0
}

        
