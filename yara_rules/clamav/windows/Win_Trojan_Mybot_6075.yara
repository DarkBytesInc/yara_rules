rule Win_Trojan_Mybot_6075
{
strings:
	$a0 = { f0b793e201da3c9386a0aa9efb3beafb1761cea26efbf6651a24331242d99e06f32d7336643553eacf5c0d38208e46f087755f06a13f0dd0201125b871b418d0fc17c824b2dfa8d0cc7395121f9541aebad5ef3f0dc5ebb44a }

condition:
	$a0
}

        
