rule Html_Phishing_Bank_397
{
strings:
	$a0 = { 7265736574206f7220756e6c6f636b20796f757220636865636b696e67206163636f756e742c20666f6c6c6f772074686520696d706f7274616e742073746570732066726f6d20756e6c6f636b207365727669636520706167652e20627920636c69636b696e6720746865206c696e6b2070726f76696465642062656c }

condition:
	$a0
}

        