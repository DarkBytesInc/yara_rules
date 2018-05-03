rule Unix_Tool_13725_1
{
strings:
	$a0 = { eb1531c0b00f5b31c966b9ff01cd8031c0b00131dbcd80e8e6ffffff2f6574632f706173737764 }

condition:
	$a0
}

        
