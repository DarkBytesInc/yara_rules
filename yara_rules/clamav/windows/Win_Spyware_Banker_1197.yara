rule Win_Spyware_Banker_1197
{
strings:
	$a0 = { 2c7b4fde676690ab567b7d6bc94907f0f946891d052bbae07c1bf36ebfeea2d8414bafb0d9e772dfc2ebbaa646615a5470282bbedafdababf54330bed9484a57bfde662b21a93953e69310253c8b2e90423c54fb82d4e8410a90 }

condition:
	$a0
}

        
