rule Win_Trojan_SdBot_3814
{
strings:
	$a0 = { e6fd3e2464c9af716b3baa1412fb2daf351c1e7b7be1eded8d5776b5df73f9f79a07235ee504e9e6edeb6eb0d358b22add6f27784248886dcf50aaf55591ba0b05e3a03f37a97d21d58a31d9d3a3129c9a686993c6660907ccb179cecf017935684e }

condition:
	$a0
}

        
