rule Win_Worm_Stration_351
{
strings:
	$a0 = { 54033c2e389e218216502e9782dde86671b2a75c8161fb2704baf352d0f4fc4882434ce371a40651d6dacd5b4a63735a9cb416e3ee7520418cb7ed2057294ab89094498b64f95c6727f5cfb92c6fcfff }

condition:
	$a0
}

        