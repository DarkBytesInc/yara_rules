rule Win_Trojan_Agent_35563
{
strings:
	$a0 = { 558bec81c4f0fbffffc745fc000000006a006a006a006a00685a904000e8900900000bc00f848f0000008945f86a0068000000806a006a006828904000ff75f8e8730900000bc074708945f46a006a008d45f050ff75f4e86209000068d41f4200ff75f08d85f0fbffff50ff75f4e851090000 }

condition:
	$a0
}

        