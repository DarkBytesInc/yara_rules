rule Win_Trojan_Agent_35216
{
strings:
	$a0 = { c731800f6606e9e4066da3ca29cb415883a60680166fef4cec13925b2a60f77bc527a76bfcec7ea450a9737ed435f31e9e6e60e8a5c41db9fffeee0924adc421d7a264a539dba751860fc315ab50 }

condition:
	$a0
}

        
