rule Win_Dropper_Agent_33446
{
strings:
	$a0 = { b457d95e6ca2be2a590a9ee516894cc076f81ef401877c70ae60388b8ae4090da295bbe7b88818af0708f3e7cd31193affcce65e9bcec1d0244a33e087648a99f6acf6fede34e1ea6e00ac9e857ecff9f2638ffd7502a7de11dc2c1414a1a8e8794c266dd7f9 }

condition:
	$a0
}

        
