rule Win_Spyware_Banker_1213
{
strings:
	$a0 = { 857dc5c23befe336cd245239dfa9fc5a2e692218ee83cda45fc3c2df283b06b0bcc9327fa84c3e767e9d060a0b7c48c2b3fd5f9b003e5612c6ef33a2d655a5539705261fd2d1352e377deff42eed8be2c3f2a79fc88ac2926add }

condition:
	$a0
}

        
