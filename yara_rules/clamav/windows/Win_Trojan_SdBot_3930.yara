rule Win_Trojan_SdBot_3930
{
strings:
	$a0 = { b0e24c94df45cb1b5a097ab16b996c110773e98fab08cb16c364ee13278f51d4e1c9864885f4f3e0073bd8fd2de77f8b2de03ef816d5536f0999dfb0c7a9245d92d6edb6a5e2c9ff18d1eb2031772659eace7ab050a1f99715adabe7 }

condition:
	$a0
}

        
