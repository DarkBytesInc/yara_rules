rule Win_Trojan_Mybot_5186
{
strings:
	$a0 = { 3f31f66e5131066e4131166e7131266e6131366e1131466e0131566e310b66e3733c76e0d23b86c4c19b96c4f19ba6c4e19bb6c5916b78c5816eec25b97af90e5202e99b792f3a70192f5e70052f56700d2f6e70352866a64f3df8a7b8f6fad97846b619ed46ce19955e80799d41def05d50a93bf684a9c3f690a9cbf5a85ddf799b22c4619b3ac4199d4e51723e7a8b399472efcd3d }

condition:
	$a0
}

        