rule Win_Trojan_Mybot_8381
{
strings:
	$a0 = { 3e99aa1b507ecc83a31b64ed18c353f1f69e341931410dea8cd6bdb0dcc3c0e31f78712146de0ed6cafc0bd38e05b31220ccaa774ec531c92512d64ccd4744fdcaccaf6f21ff8ed3edcfb32190e4efc8d23cccc439 }

condition:
	$a0
}

        
