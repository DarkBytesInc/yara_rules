rule Win_Trojan_Mybot_8418
{
strings:
	$a0 = { 79aa6c138d301980ced461d493b46f41ed78e21999b28ab0ab98d7c53e7ca0ffc63c929d230ec925083d0e3791454600f4bd9c45a5fc6a57bf75d78d92fd95c2c8efa82a365adb97dc207f69eb24b736ec3e52be0d }

condition:
	$a0
}

        
