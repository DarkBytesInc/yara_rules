rule Win_Trojan_Digress_2
{
strings:
	$a0 = { db8edb8ed3bc007cfba113042d0200a31304b106d3e08ec050b8470050b80202b90200ba8000cd13cb }

condition:
	$a0
}

        
