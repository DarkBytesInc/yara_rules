rule Win_Spyware_Banker_1156
{
strings:
	$a0 = { e34dd474fbbb5bf0e7e0b28173f0aac39f4a6778fa4db3d6ad2c4ba260d3290fa5f1731593b9d9acc9dcc6753b10483655af63af9dd1bc6fa5f5aab0721c443b7230be925c411f8e9a3343b1fbe211badac4c774f1cf5fd607b9 }

condition:
	$a0
}

        
