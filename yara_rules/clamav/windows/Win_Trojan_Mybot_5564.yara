rule Win_Trojan_Mybot_5564
{
strings:
	$a0 = { de2e450df8101c018a4259b150a30d62bb0bdbd2eb61af34e433bbbe96e13305edd9705dee97193ae3da25d9b8262d6bb6320d4ab33e55a6f7e4a44f26822096ede0a56d5c1df4f91a11ab16a1929e13a3b342d549ba5c99f01fbc76a2701b91 }

condition:
	$a0
}

        
