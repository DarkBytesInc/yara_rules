rule Win_Spyware_Banker_1217
{
strings:
	$a0 = { 14a0618f6cef26a988afb80e93459988a928412e9b3e131f545a5dccdef7c469337d297c197b88cb212ad4cf81973809be03dfdddf8fc948638e7c3b0f8cb2aee32ea360b4fde10d54ecf72897070706b3de7947e55ccb78f5cc }

condition:
	$a0
}

        
