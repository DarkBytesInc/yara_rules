rule Win_Trojan_Hupigon_872
{
strings:
	$a0 = { d6d0b1f9afe4b5d533a39cf5a26cd65423ffada1028d87eee9648372a0dd36eee5a5df4ae1bab6723e13ea49a56bd2476933afe85c29a90e8d8380ef177bde37f97b300810151a7a8fd907212d202dc9aae09c7ec01ab5de7b19d8528d54e7 }

condition:
	$a0
}

        
