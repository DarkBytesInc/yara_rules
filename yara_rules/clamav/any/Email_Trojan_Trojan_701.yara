rule Email_Trojan_Trojan_701
{
strings:
	$a0 = { 4375207374696d612c }
	$a1 = { 66696c656e616d653d22776d787065726b2e65786522 }

condition:
	$a0 and $a1
}

        
