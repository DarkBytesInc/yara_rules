rule Win_Dropper_Small_5036
{
strings:
	$a0 = { dae2b00c0203681740f28240ff75081b8945fc407504b5a0b7300c8d45f850b73884c5100cfc67f26351750fb62c9137b0905800e85368d0564000687de85bff566a39000bc00f84cf00ea932c28683a04992db7895185b3832369d90c87f46a045a2c0b601090c2eb2847fcff1513602766f833db6c342d1c747ff4f78c5b26f8dcb0dc4e5e54f0c864e139 }

condition:
	$a0
}

        