rule Win_Trojan_Laroux_70
{
strings:
	$a0 = { ea000000ad0015004754484d534e5a2e584c53214754484f4d534f4e5a002000600028006a0000004f00ffff6a00ffff9a0080006b00ffff8e046400c0002a0220004002270034022000340224004a02010027002a02000020002a02a3001e00050020002a02a3001000050003009400ad000e00433a5c }

condition:
	$a0
}

        