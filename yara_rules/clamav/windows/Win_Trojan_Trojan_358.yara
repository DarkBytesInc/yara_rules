rule Win_Trojan_Trojan_358
{
strings:
	$a0 = { 54aa2b9e745e2fe015ce9bdca3db09d59e84b13ba5ae6f3797508ec9c81b6030c4ce20293b49a622e73eeeda2811b032a9d414d6067dd9e42a8827bc7943c4d7590ed6addd12776546580d9b1487cf370c9bef3aacf8bef3f256dad3ea4efbda1ce8a4ed5a }

condition:
	$a0
}

        
