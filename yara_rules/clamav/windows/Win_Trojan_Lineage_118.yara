rule Win_Trojan_Lineage_118
{
strings:
	$a0 = { 38e403f4684dcfb5dd8b96187679775cce6c7c1dc0f7b16d2de8710d54b65808e60cdb54503da354a1ab1d2bea8c9b85b5a8c1c35e8e1b2b1db0da0e438a90a6a2f5662b194093d2de9afbeda6d77016191c97a3e21ba4cd6fe4e7a7dac4ffca412b5625 }

condition:
	$a0
}

        
