rule Win_Trojan_OneHalf_damaged_1
{
strings:
	$a0 = { 4ccd21901182219ae550042aa1cfbc25b639fe9b0d6f64d17e6ac98470cd0eca459044391eb2b134394d4152a5a945a6ad130ef553c65ce304ae61174bcc76d179f17562f558e471de9af944104dce8ac5300459bea2d12428adaeb2251834a19eba391440cd8eca750054f97ed2 }

condition:
	$a0
}

        