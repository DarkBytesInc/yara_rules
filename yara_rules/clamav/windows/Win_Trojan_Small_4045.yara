rule Win_Trojan_Small_4045
{
strings:
	$a0 = { f8be6651a6fd81d69a029a02568dbebc86ffff81c700800000e8190000008da8ddaaeedd192e8db6d902000081eed502000039f775e3c3b8e85a40008b006a00ffd0c3 }

condition:
	$a0
}

        
