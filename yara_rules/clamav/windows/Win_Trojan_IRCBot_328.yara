rule Win_Trojan_IRCBot_328
{
strings:
	$a0 = { 717fef65cdfd516ab6c8eee26cd9b0dfed606e928f886457d54896e14dcbcc74c3e7dbac0cd395c96b8f2095bab96b6a8ed5cb9cfcc3f361c031aec0b48aaf69b0b0258eb0a86e5fa57bacb227561fae40df9e93289b81a3a5a3acf88e0d9b9d0d2b553a88838233058475c5 }

condition:
	$a0
}

        
