rule Win_Spyware_Banker_2689
{
strings:
	$a0 = { c20218e0bda5e9195a091344c93d4bb65e95b63156b5425b5860d56529bbd6ceda43b979c3c430f2da9282318b5e68d01284fefa4da64f0582c36fd39b21c649a3eefedbf666ad729da2023700ac }

condition:
	$a0
}

        
