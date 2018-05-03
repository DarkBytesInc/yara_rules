rule Win_Worm_Stration_373
{
strings:
	$a0 = { b1b8f8036b5c974370716c25c366597f8fb290714be04d3e6683b6d56ad59a77803aa4fc3eaff504ce9382f10aae4b97323a45912619e87e8e4ab6471cb93df484f0b4254d125fb768a8ec2389dafe6c }

condition:
	$a0
}

        
