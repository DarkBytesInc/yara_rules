rule Win_Trojan_Hacdef_69
{
strings:
	$a0 = { 5b68696464656e205461626c655d[0-50]5b68696464656e2050726f6365737365735d }

condition:
	$a0
}

        
