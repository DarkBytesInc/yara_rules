rule Win_Spyware_Banker_3372
{
strings:
	$a0 = { 6ae93d71f064ec9dca469e2ba57b2cbb6c775342255cb73db2e284fbcf0ad74e7b144c60dd97b6e92b3c3e5471df7716603e31be4dadfb8f2629d5312bbfd294ce11fd5fa71aa769a4905a1dd8aae908245d0f942b }

condition:
	$a0
}

        
