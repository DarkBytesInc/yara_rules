rule Win_Trojan_Mybot_4493
{
strings:
	$a0 = { 48d67118414f0edc484663dc6965adee5fc5d99e06cebe89cf578f1993c151ec6f9c89a4abead5bb85dd2a0c182b6944bd597dbc6cdd664e711f2ae46a8a57ae43794886143cb67f83146f4e92465ea464d73765bf5545a6bfedc49fc8efefe54cde1fddbe }

condition:
	$a0
}

        
