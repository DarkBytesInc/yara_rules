rule Win_Trojan_Agent_31578
{
strings:
	$a0 = { f183456753f10e8fd3bd279b80da32aa9c911c442ad07b03b472725fa319d9dc637733238ee573368716d958de53cebbac281dbb5fd043924f8b3c5f87e3286440e69a5487d3fcd3456d4b6ece3f4c0d17f77cf862b74e03fcfc0b00f6b74a2064d7ea31eb583b8c451589ff6bf17367abe802a2ee10731213d4988e6df677 }

condition:
	$a0
}

        