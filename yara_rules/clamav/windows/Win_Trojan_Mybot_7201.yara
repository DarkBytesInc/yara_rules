rule Win_Trojan_Mybot_7201
{
strings:
	$a0 = { 566f73e9a3438d80354b88d4e98f7c7247e198a3fc20f9e95d7c4e56991fa0ef8fa7fe23a636705398cae6cdb257acc5b8f56c0ebd6bbb1bccaf155a6a897e6bd9bfe9346f30aa9becab2620c4aabbece56b1d178bad71c8f1cc34c04d9aafaaa969f8022bc2bc9c36941173cf418dbbc7b95870a65060f46442c5 }

condition:
	$a0
}

        
