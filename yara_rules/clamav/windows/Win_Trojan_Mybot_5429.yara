rule Win_Trojan_Mybot_5429
{
strings:
	$a0 = { ea68d528df2e3f8ecadbee1da45d5b28819d1165e56a39de06a3ea7a013e0c98c310022cf70e0b804b8c93a2b8d7967eec0008f5eda567e9765da09d9b19c33530837cbe338c0e8d9c8c6b84dc37f8cffa367c1778c4fd4317dcc435e2c9102e6541eeeaff4400b33f01b58c88ee6ae2876450d12b33f6c8a0dd81006cc9145ce2cf58ed63cf39a5153350ac }

condition:
	$a0
}

        