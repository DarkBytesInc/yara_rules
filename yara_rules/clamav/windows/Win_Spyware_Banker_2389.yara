rule Win_Spyware_Banker_2389
{
strings:
	$a0 = { 6e009ce4ac8252c603e5a09145f57aaa532e2ddddd26cce92a2c537daab9b3235ed8fc1cb68d51edb66bfc84902d4c78d6e366a8bc2dc89146c5f4472d4bfaf45a0fbacceee2cf6ff9e97c1b9fe6d36cbca08d552a0f275c142ec78961bbab4250a3a2ae2a33c1084842ccf4a935596a6e10af959fa0462a78814ae2257a5f8f }

condition:
	$a0
}

        
