rule Unix_Tool_13252_1
{
strings:
	$a0 = { eb1b5e31c06a1a6a1759495b8a040ef6d330d888040e5085c975efeb05e8e0ffffff0e6fc7f9bea3e4ffb8ffb2f41f954cfbf8fc1f7409b265 }

condition:
	$a0
}

        
