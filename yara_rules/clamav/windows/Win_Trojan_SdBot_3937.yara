rule Win_Trojan_SdBot_3937
{
strings:
	$a0 = { ffa4806d7ecba52e925f98b0c71d9d8dbaa8828dd342e636364aa7b248727ac9da382d03db4638e024cbe7fa1d908acb83f33043fb9bafef2c6fd2d71f11df75bf13c19570a3b330d75d53e767e6fc79c1bc7b0db1c3083ae665f73c }

condition:
	$a0
}

        
