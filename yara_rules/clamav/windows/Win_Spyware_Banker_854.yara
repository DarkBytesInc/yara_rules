rule Win_Spyware_Banker_854
{
strings:
	$a0 = { 4518866afc3567250a6c74da445ecf1b86a6d841d89ff02c1e196a8189557d18859a885cd9e46e4a6ec96db72b651f75834345c2988b6aecbd20792c90df8c8f8a42f67a07fc7f95e505d4c057ed2fc443f32ca5bb639495a95d5c8b4302b1a8e931119a899bd5ebc0982d819a5b7c94614879dea34c31076e491501c0f8778d88c845d8ff40bc77cb536b98c936ba558c6235a169dd }

condition:
	$a0
}

        