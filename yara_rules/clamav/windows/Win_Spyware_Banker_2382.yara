rule Win_Spyware_Banker_2382
{
strings:
	$a0 = { afd149da0ea74290dcf4eadc291e8c06d5f6f35280986d2a44f1c5e7e45b9010350f050cce238be9243c9c0b7c284eb81274945a70b51d708778bb553f8ca22e0f4188ffa77d158094302f951dabbb6e5b556cac194f5555897744a8b6862530cf9620aeb9904b111cfea16b99146b733b3edc88bff0b721f50b3196adacc094 }

condition:
	$a0
}

        