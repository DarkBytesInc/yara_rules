rule Win_Trojan_Agent_34907
{
strings:
	$a0 = { 4ee604d532ce61a6daea7ab5c5f061ba91d76b2bb498f9a0fdf669dced865cb1dcf67a2bcee2f5b191c97cbbbefd7ba6b8da6fb8ddb92686e1da27f4f9fc62020837bba498ba39a3f7af6df534e41522d8ed77eb97d75d879886 }

condition:
	$a0
}

        
