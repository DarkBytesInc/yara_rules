rule Win_Spyware_Banker_2056
{
strings:
	$a0 = { 73a0375bd1f5a72af348dd5dd6c6cf60c6f8ba02f9174882b4ae10422651bdedd7eedb512630ad4b2ca8ff8e0cacc9f5d7fe41e6f6b86e201ac7c5fa1dc4a2fef77ffee524ea4cdd63f5af7207dab6005c4e4fc6e6fb73a6b193f866f8da22df07a4ff938e20122b39fea960353b45bebab710cf94fe1894d07386ac4accad91 }

condition:
	$a0
}

        
