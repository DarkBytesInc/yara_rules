rule Win_Trojan_Mybot_8391
{
strings:
	$a0 = { c4c05ebfc475133d61f5635494ca314dddadf9b8d46fd9e54a495c689e224c0aa90647831e5a997145f925fa5c7aeb370af65e1cb81a2dbab36413663d524b418e0b622e12cf4e6200b77dff33aad8cec4a06d3adc }

condition:
	$a0
}

        
