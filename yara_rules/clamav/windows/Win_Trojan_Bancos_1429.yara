rule Win_Trojan_Bancos_1429
{
strings:
	$a0 = { 72a028218423babd3bf177ec5f22c7d01d7cfc37ce0eb716ec3a5de1c9134fafb706ae48d35ffe4c7b41e0a65ac25d4cb1d580e09c4f9951ddacf5ee0ca78e0981dbdb2c76194b7854993d4fc6552c0b397bae2f4f43dfb41c }

condition:
	$a0
}

        
