rule Win_Trojan_Codbot_4
{
strings:
	$a0 = { 73197036a1b65099dbc816b551a87d04a121633906567d95f05639f0fada3e7184e5c65f728cd2325b436c7c0bd45b3e9f4dc6f5bbc8b0df8954f16a73f1b7dd34608abd0789ca47eaa8c722b0d5b2ca66165cf201c2e9f1e85f286d37fe28bdfe63115515408338f4f4c556a25dadc3c2713bef664b306d65d418feb8e63ded2c5f0466127655cbfcb94043b597cd7ee5d0b3c3c1 }

condition:
	$a0
}

        