rule Win_Trojan_QQPass_64
{
strings:
	$a0 = { 0052408a828a323a51880840226f52436c1bcab5b7bf8b7b9dee53f0efe03cee677205bce640e5bce406de76056aee2dab05ed6ee41784825e39016dc906f1cdc1b5c82dae4856dcd8b8dc9015c80dedc817b7b906f3b7203cbcc836f7982b6f72de6677bfffffedf7fbe7cfbf75af3cfbe6bef9e6b5bdfedf3dfe045cd102694c168b459f76b1ef44487caf }

condition:
	$a0
}

        