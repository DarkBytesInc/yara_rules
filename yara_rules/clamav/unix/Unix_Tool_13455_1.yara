rule Unix_Tool_13455_1
{
strings:
	$a0 = { eb1b5f31c06a536a1859495b8a040ff6d330d888040f5085c975efeb05e8e0ffffff1c7fc5f9bea3e4ffb8ffb2f41f954efe25979330b639b22c }

condition:
	$a0
}

        
