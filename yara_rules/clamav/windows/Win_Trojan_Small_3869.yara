rule Win_Trojan_Small_3869
{
strings:
	$a0 = { 9def856e92ede63989e9eeac17fccb661380b25d2a03739e14365ae4131f8beb6aacb3b16baa77a225eb61c81501b5c6dcc6a15efc07545e142e266f6b15625deafb607464bba15e7ce73c9f1438a6823813067a54abb1b1dbef858e14ab615efc7b9b5e1436ae82 }

condition:
	$a0
}

        
