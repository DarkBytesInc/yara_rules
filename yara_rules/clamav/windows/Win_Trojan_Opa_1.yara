rule Win_Trojan_Opa_1
{
strings:
	$a0 = { 7b005589e531c09a7c027b00b80000ba0000a3440089164600bff2050e57b8200050bfca031e579a42006f0083 }

condition:
	$a0
}

        
