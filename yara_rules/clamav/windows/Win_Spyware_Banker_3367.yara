rule Win_Spyware_Banker_3367
{
strings:
	$a0 = { b311b4fda24449c5cbcbbbf8c6b157225df9ffaa6d04d616d600d3acbe0ad35b470034aace7cc88a407a3212214d3399443cf26e495bd88f91b16e718468b1f1dbd6c3ab15cf964d4beb7c8c7f74d178696cc9b41b }

condition:
	$a0
}

        
