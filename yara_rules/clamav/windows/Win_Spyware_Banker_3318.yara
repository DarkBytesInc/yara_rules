rule Win_Spyware_Banker_3318
{
strings:
	$a0 = { d7f787cef3fef84f214d84567825d7429c04dd04312978c41b71c82040cbe10946359b88491e81df8f9fc522edcad2a692c4eddc883e407011beeb38678f5450171cf5215b3c }

condition:
	$a0
}

        
