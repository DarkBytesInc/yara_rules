rule Win_Trojan_SdBot_4251
{
strings:
	$a0 = { 15596376e9dbeccb002ba8badf8d54d6800524f05d80a56f332d9dc45f977928c7c85190b4715cab84d668f578dc84fa193aa09f151152f099503d86f9e259f383492514f12f409ac58c345345748847c716731156d6e77411410a5388f7ba4a420a44e18252aca361a8ff03cddebaecc1ed657ca0da5b07f88fa72f04065345a05613c1 }

condition:
	$a0
}

        