rule Win_Trojan_Sinop_1
{
strings:
	$a0 = { 696c652876696374696d6e616d652c2032292e5772697465282753696e6f70652829272b6e6c2b766963636f6465732b6e6c2b6d79636f64652b6e6c2b276675 }

condition:
	$a0
}

        