rule Win_Trojan_Mybot_5726
{
strings:
	$a0 = { 44e51dff03335f4c0aaac97cff0ddd3c710550aa41ff022710100bbe8620ff0cc925b56857b385ff6f2009d466b99fe4ff61ce0ef9de5e98c9ffd9292298d0b0b4a8ffd7c7173db359810dffb42e3b5cbdb7ad6ca8ba9740b8ed }

condition:
	$a0
}

        
