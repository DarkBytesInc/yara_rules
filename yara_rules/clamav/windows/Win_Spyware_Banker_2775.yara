rule Win_Spyware_Banker_2775
{
strings:
	$a0 = { 1c4f8d9779f368eb2feb9f3a7690eccbfbde90525fd6b6b2ad81bb8146e23ee54d787ad2d95b601f24842ed56ba1a57f90e5bb3b889208052e09bdafb0c2ca6a77eccba540f87d2d0d46517a5f80d5c4296ad1410f8c8a1efd7d02f92b25793a57abb48e }

condition:
	$a0
}

        
