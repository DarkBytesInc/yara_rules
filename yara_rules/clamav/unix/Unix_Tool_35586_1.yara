rule Unix_Tool_35586_1
{
strings:
	$a0 = { 31f6f7e6ffc66a025f04290f05505f5252c604240266c7442402[2]545e526a105a6a31580f055eb0320f05b02b0f05505f6a035effceb0210f0575f8565a5648bf2f2f62696e2f736857545fb03b0f05 }

condition:
	$a0
}

        