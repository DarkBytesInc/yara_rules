rule Html_Trojan_Fadedoor10B_1
{
strings:
	$a0 = { 5c53657474696e67732e696e69000000ffffffff0a000000495020416464726573730000ffffffff040000004c61737400000000ffffffff090000004d61696e20506f7274000000ffffffff0d0000005472616e7366657220506f7274 }

condition:
	$a0
}

        