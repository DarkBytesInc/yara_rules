rule Win_Trojan_Mybot_126
{
strings:
	$a0 = { 0d63150e5894287bc409345111418e466e6d4473d27c2be3dd3b767f78f5708158cbb6d9a61f15c6e28ec9c263ccaef72f09c79e5fc260abddfc8555dcf9537a140c4a61b171e18cf5dcebf3f2ebfb4010e20cb5d64314361de6f7c43e6bcc53853b4852da53e9f9311c27b4d4eb31c28a6734b1785baf8a }

condition:
	$a0
}

        