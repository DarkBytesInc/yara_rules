rule Win_Trojan_VB94_1
{
strings:
	$a0 = { 9e0250e82a0959b8d40250e8220959b80e0350e81a095933c050e80d025933c050e8e50a5950e8 }

condition:
	$a0
}

        
