rule Win_Spyware_Banker_1654
{
strings:
	$a0 = { eff7f8f4547ee63c271a8b6cd2f0d24ac3ec933ced86957370c85bd09fd9e4a5d395e976e2bdbd0dc7072e25ba3c4588c43ad8eb6c345cebd57761a77b09545ac37e9fe68a17b211dd0bcf8bd3884f6b31b76b9cd004a14af38cf46d077e970e9448462ba5656d97f40524fea14ee2515d9314354cbcc5764b2bea7cbf2e1fd2a88902a9 }

condition:
	$a0
}

        