rule Win_Spyware_Banker_4576
{
strings:
	$a0 = { f4ce80ffd80192e6accb0033979c4dbad0b29e01ebd573fee792f61aceabf170e291bada4f0c9fb9b56eb9e95941a4102b3d5a8b043c6eb80de5646812909046a9311a413a5a445ac5d9ce375204fc86fb700a4da60dcb1145b0dcbaaafdefc75635dd5f }

condition:
	$a0
}

        
