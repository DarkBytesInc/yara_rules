rule Win_Trojan_Flooder_23
{
strings:
	$a0 = { 723d6972632e6f7a6d61747269782e636f6d }
	$a1 = { 3d7573657220736b617a6172407e[0-43]236775696c64206f776e65726b657920686f }

condition:
	$a0 and $a1
}

        
