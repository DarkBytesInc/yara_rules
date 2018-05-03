rule Win_Worm_Gaobot_596
{
strings:
	$a0 = { 42add2afc3018c29002d4eef157071e85a0ba0fb666a7700c1c08e7b1107447e795df16029f99f5458ab681dea6e40d3a9802692cc00e71e17ae236a0934012ccd3ee5806493e3f0fd9fda }

condition:
	$a0
}

        
