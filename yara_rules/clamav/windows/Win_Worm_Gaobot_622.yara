rule Win_Worm_Gaobot_622
{
strings:
	$a0 = { 4f8d141f565f951da6f0d83d1d8a162714ffea5663f09bcf2b096b594871970782d6af57c1fb5cef89f72d19f258302e44ba339eb55bf4eefc850d56c35296079315c07232316de7ba934608f9123e9e61567d726de5221738fd0729d70ce3e7b760e2b2caebc7076e6f3029850190bfc57aef52e9a9a437ac19f929933b4de78b0574b3e78859089aaa4a219857c1d129e6d233e996 }

condition:
	$a0
}

        