rule Email_Trojan_Ecard_42
{
strings:
	$a0 = { 6174746163686d656e743b2066696c656e616d653d22652d636172642e7a6970 }

condition:
	$a0
}

        
