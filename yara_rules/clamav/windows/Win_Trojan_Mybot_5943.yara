rule Win_Trojan_Mybot_5943
{
strings:
	$a0 = { 1ec3e87d16e30bf99e3b0326e5ef6987668370f64f8605e79ee0788aa2ae9ef123d2ae9cc9a4da619a2aebf4d6eb0dae11730e1af5096b4410e12d432b4136df3ef5eb68fe7c2bde9e1d5afbf41a2aa42aaea3d72fe35fa18654404552f04f3271e3ba43d6a76639 }

condition:
	$a0
}

        
