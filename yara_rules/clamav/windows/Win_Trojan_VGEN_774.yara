rule Win_Trojan_VGEN_774
{
strings:
	$a0 = { b80012cd1658bee20150b80012cd1658bb400150b80012cd16585350cd1158b80200902e8b3ff8c1f7017301474883 }

condition:
	$a0
}

        
