rule Win_Spyware_Banker_1173
{
strings:
	$a0 = { fade66d6f7d672cebc7b0503284bee74afef1a2b7e7ec54e14eaa38d76789df5f638a4936f3544428b23aaed4da4b0bfe0b5252694c51add7e8e3514d68fb13190a4e452b5d93e8d31f68105f2343e9ececd43c32b2632475405 }

condition:
	$a0
}

        
