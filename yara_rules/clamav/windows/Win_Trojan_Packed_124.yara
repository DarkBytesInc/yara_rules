rule Win_Trojan_Packed_124
{
strings:
	$a0 = { c745f400004000c745f0????????8b45f405????????8945f4c745fc00000000eb098b4dfc83c101894dfc8b55fc3b55f07d228b45f40345fc8a08884df80fbe55f883f20f8855f88b45f40345fc8a4df88808ebcdff65f4 }

condition:
	$a0
}

        
