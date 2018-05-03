rule Win_Tool_FWbypass_1
{
strings:
	$a0 = { 496e7465726e6574204578706c6f7265725f536572766572[0-24]6f70656e[0-78]6d30726f6e }

condition:
	$a0
}

        
