rule Win_Tool_ICQ_1
{
strings:
	$a0 = { 10687d974caf589d7a64cca009b692820971f08746115a40ffb4395624ce0d99f47f7ffb018ddfbf55730f456d61696c044dd35d4f5437e16b33c3c5f7140b02 }

condition:
	$a0
}

        
