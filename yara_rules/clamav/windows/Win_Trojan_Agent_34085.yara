rule Win_Trojan_Agent_34085
{
strings:
	$a0 = { 538d1981eba80f890187cb5b51b91420902881e96c100727010c2459894c24fc83ec0481ef6f7cd13681c76f7cd13689 }

condition:
	$a0
}

        
