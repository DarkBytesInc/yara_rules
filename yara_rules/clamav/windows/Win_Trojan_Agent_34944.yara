rule Win_Trojan_Agent_34944
{
strings:
	$a0 = { c31de95ad61432f32a54e020cd37be5d8a817ede3a0c9f6cf8476d65f4521d425e0e7809035ba004b9ef7bdff4eb173c78cfe88147145c225ffcd18eeac3a54dd3694e32ca23c60e50dafaad7e2bee417f9430c5d569c4d62c9ddacc0f895f26959213e22e2f8e2dd1838c4f074bce2e5ce61530c4f02862ac90b43d7de4722ec8c044efa069fa7134929041e78ff30149259045e3e7 }

condition:
	$a0
}

        