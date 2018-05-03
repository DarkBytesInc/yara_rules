rule Unix_Tool_13428_1
{
strings:
	$a0 = { eb1b5f31c06a286a5259495b8a040ff6d330d888040f5085c975efeb05e8e0ffffff0e6fc7e4fffbecf3f4b3a0eef6b8ffb5ee0295913ab57032ba37b2f6b5bbb20407865c21b22ec6f9bea3e4ffadeab2f4fea7f5ffeab8adfff5f5ade3bbffbd3f596633ba7297d3b24e0e8f4934b23f72b257 }

condition:
	$a0
}

        
