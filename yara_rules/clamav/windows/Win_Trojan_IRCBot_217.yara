rule Win_Trojan_IRCBot_217
{
strings:
	$a0 = { 6ab037eae6a929e8ea8adbad9b01e2e35081c7148dc371a0124e2cfc30be68d4d6dcd028a0a5a55cf11ba7dffab3be5a44be8026d90cbffb2ee17b85af1f5e3b9d8520b3f6d9dab8f59057d9455bf386856292c4afa7ae6839a2112d54df6c7a265e678c8e2e3b9ae4 }

condition:
	$a0
}

        
