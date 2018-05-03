rule Win_Worm_Sambud_2
{
strings:
	$a0 = { a0ee4822e785186304a6825930a907a921cdd0eba40fd4805cc803e01b513f30583f4b617a61613bc0c8602d240516ca5188b70e8ca0b1c9dbe86fd38436942f4b1a646f6d2dbe }

condition:
	$a0
}

        
