rule Win_Spyware_Banker_1973
{
strings:
	$a0 = { 9eaaf2fbf703888ff2197b7f2c21d4157e2428abbc7f82efd39efbbf13e03aa1a6a239f2ef1360622de7e040deff7fe36fdffbb5aa5f9d1a88dc7dca814e71be3bbf5dd4c407fa318979f4010903a56d4c3bab43ce71f84756f49b2f807d27d32334aaf03bb273a9dca41de4817dc78550bdb5e1faf3c3800ad1eba6db641d01 }

condition:
	$a0
}

        
