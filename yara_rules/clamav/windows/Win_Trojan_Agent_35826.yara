rule Win_Trojan_Agent_35826
{
strings:
	$a0 = { 6f70656e005c }
	$a1 = { 2e6578650020253100000068746d6c66696c655c7368656c6c5c6f70656e6e65775c636f6d6d616e64 }

condition:
	$a0 and $a1
}

        
