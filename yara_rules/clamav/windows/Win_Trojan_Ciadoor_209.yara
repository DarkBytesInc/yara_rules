rule Win_Trojan_Ciadoor_209
{
strings:
	$a0 = { 1c4db1cfe6a69072f26e2202ae2f872cc1fe617fa211ecd6336cb5c9225fd4d72f7d025f5ca447a1badfa864a6c53de0b6986f37362c781ca5f2f21b1dd8f813507a20f09c3ef0ea183de9b46c04c0ee72fdbe71e47a9783f446a37f73ac226ee365d14b }

condition:
	$a0
}

        
