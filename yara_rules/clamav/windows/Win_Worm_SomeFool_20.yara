rule Win_Worm_SomeFool_20
{
strings:
	$a0 = { 9a456e42531cb5c63f3f340e9e1639fb675ff1c1a3b1349aeacfdeadc2ff305ef89a71f612652c6aba5702c8c6d02c23 }

condition:
	$a0
}

        
