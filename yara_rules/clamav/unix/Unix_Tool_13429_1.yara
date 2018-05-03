rule Unix_Tool_13429_1
{
strings:
	$a0 = { eb1b5f31c06a536a2959495b8a040ff6d330d888040f5085c975efeb05e8e0ffffff03b69007be39ba796c8720f048cf0e8f403db24e0e7f72b297f3e4ffff2fb5eee8b3a3e4f6faf4e7db }

condition:
	$a0
}

        
