rule Email_Phishing_Workcenter_1
{
strings:
	$a0 = { 646576696365206e616d653a2078727832373034616137616364623439303433353934 }

condition:
	$a0
}

        
