rule Win_Trojan_Trivial_361
{
strings:
	$a0 = { 4eba4a01cd21eb0d90b43ecd21b44fcd210ac07531b8023dba9e00cd218bd8b43fb90200ba5001cd21813e5001b00074d8b80042b90000ba0000cd21b440b95000ba0001cd21c3 }

condition:
	$a0
}

        
