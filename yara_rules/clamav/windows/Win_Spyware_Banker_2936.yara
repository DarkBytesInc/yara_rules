rule Win_Spyware_Banker_2936
{
strings:
	$a0 = { 62eb53d31d76dbb0c4396d1aacab2744f1aebe824fbb0b75b07be9967b90e1ed0a7c5620c29818684eb6b58d3bfe5abe5f4e29eca4eb7164e6998dd53e36876084aa34e089b00291b0ad42c6a4faa79c1e6e68ca68b498db6dbb393fd662beb52eeb853ff8af055e4addbaf3662a }

condition:
	$a0
}

        
