rule Win_Trojan_Trivial_370
{
strings:
	$a0 = { b000b44eba4901cd21eb0cb43ecd21b44fcd210ac07531b8023dba9e00cd218bd8b43fb90200ba5301cd21813e5301b00074d8b80042b90000ba0000cd21b440b95400ba0001cd21c3 }

condition:
	$a0
}

        
