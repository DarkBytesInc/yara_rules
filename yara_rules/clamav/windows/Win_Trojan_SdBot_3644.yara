rule Win_Trojan_SdBot_3644
{
strings:
	$a0 = { 385db973c7aec1ef682f3cea01dc50c1504d324fb5148ace7f8dc26092f80706a86347e32dd1141135bb6048c4f497294ffd22a0f8cc8cf1a15fa19b8d0cb6fef53ad569516f164ec0378e5161ff }

condition:
	$a0
}

        
