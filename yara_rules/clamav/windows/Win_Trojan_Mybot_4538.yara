rule Win_Trojan_Mybot_4538
{
strings:
	$a0 = { 1e09646df065cd0cbebec4a698194bc443189f28edc7b84c8c4651ef4618f22ddc0c6c159e85dc034e4c3fb2d89835e25941db6cdb45ac90451d78f7435264ecabac3a8528805757a1588cc7897c0f7e14be6ec0f3c97f6c0068b252795bdced2c2f1b194e88495f46823489c75da9ae8fc54fe2bc7f63db22847ec38d39dd737ed401329a597493a5f888c411f1b9300b39bd4daa34 }

condition:
	$a0
}

        