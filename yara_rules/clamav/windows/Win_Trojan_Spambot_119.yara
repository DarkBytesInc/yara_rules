rule Win_Trojan_Spambot_119
{
strings:
	$a0 = { 9edba85dd1c7b3835f5544bd0bc7bd0fc3be819118beaf6d287c1e067c688b23fffffff0cf6387d3abd63f5534fd4e49988931d8c2b1a7ba61e7dc5cdbafff7f80ffa6284c838d6e0e62b8032659c9a701dcfb65e01b392cedffffffff90d4282045afe5c0b86abbc4be0b7995c3 }

condition:
	$a0
}

        
