rule Win_Trojan_Mybot_7856
{
strings:
	$a0 = { d8a660c5eb8ba2110622d1691745221062f591745ed842122b1045ed045ef4c5eecc562e8bb22b1064117cdf826fc33ff66fb39d9ffb79d7cecdf66fc779e19cece78a73dffdc79f7de1ffb5f6b5fb5a721519a0f9ddc794c87d91cd4c155b5ba376db31e9b07ca608bd2a2b9070e9a6545e42dcb442eea3cfac16cdcb }

condition:
	$a0
}

        
