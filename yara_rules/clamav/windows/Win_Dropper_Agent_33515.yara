rule Win_Dropper_Agent_33515
{
strings:
	$a0 = { 0e8af15d7a14a9a2079638e5a5032702ddfcccf39c7a856b344cf627edf15995a1a1f453b7a8f2e73e34910cfc3fc3cf76127f9e97396a48f47778a676483aabea4e6fc29afd9ce80bbff8987c13b2abd777ef27 }

condition:
	$a0
}

        
