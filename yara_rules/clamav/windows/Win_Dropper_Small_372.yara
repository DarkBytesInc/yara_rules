rule Win_Dropper_Small_372
{
strings:
	$a0 = { 7572662b2070726f746563746f7220676c6f62616c207465726d696e6174696f6e206d65737361676500881300000150425a6839314159265359f69f9ecf00aabc7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe13a67cce6f5ef19f1f675 }

condition:
	$a0
}

        
