rule Win_Trojan_Mybot_8275
{
strings:
	$a0 = { b9393a81616da7512c97cb17a832262ca85cbcf712f437f6fc4528f88867c3099e5de7e492798b91ab1d5adfd8a115e7c48f62830970e650a3c17e1bb5bbe3bc8f599924758a4dbc5fa0833f1be7c51ebe6ece4f7ebb7fbf5dbb5fafe1a92ff94a9a0ccf313d38e97d4c6fa3b2184b856f7e }

condition:
	$a0
}

        
