rule Win_Worm_Feebs_49
{
strings:
	$a0 = { 006e??????757e12e4248d04c345df73b147a1601a31bfca45fb6afd7ba647c94f0161a3751cb6c41a5de39b59b7d4ab9df433531340916eb4ff52a34f91fa36b7f69277990a143066588bd198ba551d }

condition:
	$a0
}

        
