rule Win_Spyware_Banker_1474
{
strings:
	$a0 = { f6516dcad81afae6bad7435c0576f3b623f4358fecbf26c94c358b1d403db703f22346ec1cf740a76956791f6271335a8ec6188bf82e7b4a2bc6efa7fecbde68393d2f332f15871e0ee69a26ffe76591c1069dc0df27e75563eb4f376f0c6ce7719783654e897dff3e551e8bbf1393e07cfbb8ae78a8fd9ef03d1451d51016013720a96ae18a173ee935 }

condition:
	$a0
}

        