rule Win_Dropper_Agent_34178
{
strings:
	$a0 = { 6a006a006840524000ff356476400068985240008d45ccba03000000e830e7ffff8b45cce868e8ffff50689c52400068a05240006a00e8aaedffff }

condition:
	$a0
}

        
