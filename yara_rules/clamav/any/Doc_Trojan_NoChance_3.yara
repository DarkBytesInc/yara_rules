rule Doc_Trojan_NoChance_3
{
strings:
	$a0 = { 426f7820224a65207661697320666f726d6174657220746f6e206469737175652064757220433a20222c207662437269746963616c2c202256656e647265646920313322 }
	$a1 = { 6e3a3d4e6f726d616c54656d706c6174652e46756c6c4e616d652c204e616d653a3d224e6f4368616e63653938222c204f626a6563743a3d77644f7267 }

condition:
	$a0 and $a1
}

        