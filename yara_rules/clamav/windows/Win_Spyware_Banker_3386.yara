rule Win_Spyware_Banker_3386
{
strings:
	$a0 = { 6eb2c6686ed46da66589e7579ddcf0150443b6212e986b5840f184ac2b62e8f1efe5964962694fba5aab2ec0433541cc87aa2c347795c6fc6c877658523db1175bc24f6757186228f9531ceda0ef4236f066abbb14 }

condition:
	$a0
}

        