rule Win_Worm_Gaobot_701
{
strings:
	$a0 = { cef900adfa4e36b262a0e60feda7953a806e21fed8aa00e3fcde32a2906bdc0a7f64a149ed03c31b0ef2a837773f017aac436960a688ec27ca00132134e2f54c53bd0756b33d2ad8833e7e809d88030085a95be91c6e3f45073a }

condition:
	$a0
}

        
