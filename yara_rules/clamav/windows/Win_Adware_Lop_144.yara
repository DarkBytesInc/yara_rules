rule Win_Adware_Lop_144
{
strings:
	$a0 = { 4c14e3c33a6fc9e25d92e6c8f173daf3cc01c61894b4c68b1a19baf60b7a2e0ed76946afbc4e5e675431eaa6c73c983564474be30576a8b69f6c17f78a9fa26dde2a7f9b586b8ea7f96cce03a314c1a7f60034df56dba3aa87597caf040a0ec66db9 }

condition:
	$a0
}

        
