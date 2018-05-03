rule Unix_Tool_13427_1
{
strings:
	$a0 = { eb02eb05e8f9ffffff5f81efdfffffff575e29c980c1b88a072c41c0e0044702072c418806464749e2ed }

condition:
	$a0
}

        
