rule Win_Trojan_Mybot_4962
{
strings:
	$a0 = { b258862c0412dbfc13ec614fcbe7626e21e19af063d3dccb7ff029978f725385aa83b44a1b79cf739a7db09d7be9b62a5520694a56537f7c12ed49c33a986ad111587f5e7760c026a88b9f36fc92 }

condition:
	$a0
}

        
