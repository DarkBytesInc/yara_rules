rule Win_Spyware_Zbot_1337
{
strings:
	$a0 = { 68??3140005f83c7928b3fc1e7108bcc8d6f3cc98be103fd83c71d33c9330f84c9741f5f51b01c2ac8720f582cc0770abf00404000e9??feffffb801304000ff50ff6a7c59e2fefacccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc }

condition:
	$a0
}

        
