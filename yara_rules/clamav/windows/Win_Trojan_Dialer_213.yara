rule Win_Trojan_Dialer_213
{
strings:
	$a0 = { 44534c006973646e000000006d6f64656d0000004449414c584c4954452d46353744313741452d434533372d346263382d423233322d454135373734374245354537000050726f7879456e61626c6500536f6674776172655c4d6963726f736f6674 }

condition:
	$a0
}

        