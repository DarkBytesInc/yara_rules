rule Win_Ircbot_MrWormy_3
{
strings:
	$a0 = { e4fce1feb3beb3fbf6b3f0f2fdb3f4fcb3fefce0e7b3f2fdeae4fbf6e1f6bfb3dee1bdb3c4fce1feeab2b3e7fcb3e7fbf6b3e1f6e0f0e6f6b2b3beb3 }

condition:
	$a0
}

        
