rule Win_Spyware_Banker_423
{
strings:
	$a0 = { 5f34e486d52e96f24a37a3aace9db627b0283e16feed273a4c5aaececfac996aa88fe9a492fe851834c9a50d7ab61095416584757b92821e6b2a900960ab6ac127436ab8b319b2b15a8edfb2a384f13e473b7638496bb95280ec24a31c2af79ab6b1238362fc2096212cfcc2b32a835919aa7ab110261ea721fc892b7e4cb1deb2dadc05a899e847f1241edc5733025e831c82023ed0 }

condition:
	$a0
}

        