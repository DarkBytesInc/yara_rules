rule Win_Dropper_Small_5
{
strings:
	$a0 = { 5c43e1ffffff757272656e7456657273696f6e5c52756e00465245454d5a900003487b9ffbae0403ffff0000b80702400403ffff6e28c01f0e1fba0e00b409cd }

condition:
	$a0
}

        
