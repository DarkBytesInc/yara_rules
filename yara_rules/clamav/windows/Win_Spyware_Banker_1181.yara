rule Win_Spyware_Banker_1181
{
strings:
	$a0 = { 47b1ad3d27b9b7e4b7a725347a1a276e0931c3552b3c4870348097cc672f304cca9234aea0df1c0a60bf22a0bc7bb30a4f7d1b934888025f7e8f075bac8d5245e89c6dda278a1fed2939a0f96ff21d0fc479769c913de1cb6bae }

condition:
	$a0
}

        
