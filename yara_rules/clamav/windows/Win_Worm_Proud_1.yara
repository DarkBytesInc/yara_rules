rule Win_Worm_Proud_1
{
strings:
	$a0 = { 74657265644f776e6572222c20224a656e73204a6572656d696573220d0a57732e52656757726974652022484b4c4d5c736f6674776172655c4d6963726f736f66745c57696e646f77735c43757272656e7456657273696f6e5c52756e5c416e74695669727573222c20466f6c646572202620225c4d656e }

condition:
	$a0
}

        